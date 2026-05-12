/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.eltavine.duckdetector.features.selinux.data.repository

import android.content.Context
import android.os.Build
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbeResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityState
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentProbe
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxProcAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.data.service.SelinuxContextValidityCarrierManager
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxAuditRuntimeProbe
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SelinuxRepository(
    context: Context? = null,
    private val auditRuntimeProbe: SelinuxAuditRuntimeProbe = SelinuxAuditRuntimeProbe(),
    private val contextValidityProbe: SelinuxContextValidityProbe = SelinuxContextValidityProbe(),
    private val contextValidityCarrierManager: SelinuxContextValidityCarrierManager =
        SelinuxContextValidityCarrierManager(context?.applicationContext),
    ) {

    suspend fun scan(): SelinuxReport = withContext(Dispatchers.IO) {
        try {
            scanInternal()
        } catch (throwable: Throwable) {
            SelinuxReport.failed(throwable.message ?: "SELinux scan failed.")
        }
    }

    private suspend fun scanInternal(): SelinuxReport {
        val methods = mutableListOf<SelinuxCheckResult>()

        val filesystemResult = checkSelinuxFilesystem()
        methods += filesystemResult
        val auditIntegrity = analyzeAuditIntegrity()

        if (filesystemResult.status == FILESYSTEM_NOT_MOUNTED) {
            return SelinuxReport(
                stage = SelinuxStage.READY,
                mode = SelinuxMode.DISABLED,
                resolvedStatusLabel = SELINUX_DISABLED,
                filesystemMounted = false,
                paradoxDetected = false,
                methods = methods,
                processContext = null,
                contextType = null,
                policyAnalysis = null,
                auditIntegrity = auditIntegrity,
                androidVersion = Build.VERSION.RELEASE ?: "",
                apiLevel = Build.VERSION.SDK_INT,
            )
        }

        val sysfsResult = checkViaSysfs()
        methods += sysfsResult

        val getenforceResult = checkViaGetenforce()
        methods += getenforceResult

        val procAttrResult = checkViaProcAttr()
        methods += procAttrResult

        val carrierResult = contextValidityCarrierManager.collect()
        val contextValidityResult = carrierResult.let {
            if (
                it.available &&
                it.carrierMatchesExpected &&
                it.probeAttempted
            ) {
                it
            } else {
                contextValidityProbe.inspect()
            }
        }
        val contextValiditySource = if (
            carrierResult.available &&
            carrierResult.carrierMatchesExpected &&
            carrierResult.probeAttempted
        ) {
            EvidenceSource.DEDICATED_CARRIER
        } else {
            EvidenceSource.LOCAL_FALLBACK
        }
        methods += buildContextValidityMethod(contextValidityResult, contextValiditySource)
        methods += buildProcAttrCurrentMethod(carrierResult, EvidenceSource.DEDICATED_CARRIER)
        methods += buildDirtyPolicyMethods(carrierResult, EvidenceSource.DEDICATED_CARRIER)

        val statusResolution = determineStatusWithParadoxLogic(methods)
        val processContext = readProcessContext()
        val contextType = processContext?.split(":")?.getOrNull(2)
        val policyAnalysis = if (statusResolution.mode == SelinuxMode.ENFORCING) {
            analyzePolicy(processContext)
        } else {
            null
        }

        return SelinuxReport(
            stage = SelinuxStage.READY,
            mode = statusResolution.mode,
            resolvedStatusLabel = statusResolution.label,
            filesystemMounted = methods.any {
                it.method == METHOD_FILESYSTEM && (it.status == FILESYSTEM_ACTIVE || it.status == FILESYSTEM_MOUNTED)
            },
            paradoxDetected = statusResolution.paradoxDetected,
            methods = methods,
            processContext = processContext,
            contextType = contextType,
            policyAnalysis = policyAnalysis,
            auditIntegrity = auditIntegrity,
            androidVersion = Build.VERSION.RELEASE ?: "",
            apiLevel = Build.VERSION.SDK_INT,
        )
    }

    private fun analyzePolicy(processContext: String?): SelinuxPolicyAnalysis {
        val details = mutableListOf<String>()
        var weaknessScore = 0

        val policyVersion = readPolicyVersion()
        val policyVersionOk = policyVersion != null && policyVersion >= MIN_EXPECTED_POLICY_VERSION
        if (policyVersion != null) {
            if (policyVersionOk) {
                details += "Policy version $policyVersion meets minimum $MIN_EXPECTED_POLICY_VERSION"
            } else {
                details += "Policy version $policyVersion is below minimum $MIN_EXPECTED_POLICY_VERSION"
                weaknessScore += 2
            }
        } else {
            details += "Policy version unreadable"
        }

        val (classCount, foundClasses) = countSecurityClasses()
        val missingClasses = EXPECTED_CLASSES.filter { expected ->
            foundClasses.none { it.equals(expected, ignoreCase = true) }
        }
        val classCountOk = classCount >= EXPECTED_CLASSES.size && missingClasses.isEmpty()
        if (classCount > 0) {
            if (classCountOk) {
                details += "Security classes look complete ($classCount)"
            } else {
                details += "Security classes missing: ${missingClasses.joinToString()}"
                weaknessScore += missingClasses.size
            }
        } else {
            details += "Security classes unreadable"
        }

        val contextType = processContext?.split(":")?.getOrNull(2)
        val dangerousTypesFound = DANGEROUS_TYPES.filter { dangerous ->
            contextType?.contains(dangerous, ignoreCase = true) == true
        }
        if (dangerousTypesFound.isNotEmpty()) {
            weaknessScore += dangerousTypesFound.size * 3
            details += "Dangerous context types: ${dangerousTypesFound.joinToString()}"
        } else if (contextType != null) {
            details += "Context type '$contextType' looks normal"
        }

        val permissiveDomains = checkPermissiveDomains(processContext)
        if (permissiveDomains.isNotEmpty()) {
            weaknessScore += permissiveDomains.size * 2
            details += "Permissive domains found: ${permissiveDomains.joinToString()}"
        } else {
            details += "No permissive domains detected"
        }

        val weakness = when {
            weaknessScore >= 5 -> SelinuxPolicyWeakness.SEVERE
            weaknessScore >= 3 -> SelinuxPolicyWeakness.MODERATE
            weaknessScore >= 1 -> SelinuxPolicyWeakness.MINOR
            else -> SelinuxPolicyWeakness.NONE
        }

        return SelinuxPolicyAnalysis(
            policyVersion = policyVersion,
            policyVersionOk = policyVersionOk,
            classCount = classCount,
            classCountOk = classCountOk,
            foundClasses = foundClasses,
            missingClasses = missingClasses,
            dangerousTypesFound = dangerousTypesFound,
            permissiveDomains = permissiveDomains,
            processContext = processContext,
            contextType = contextType,
            weakness = weakness,
            details = details,
        )
    }

    private fun analyzeAuditIntegrity(): SelinuxAuditIntegrityAnalysis {
        val residueHits = findAuditResidueHits()
        val runtimeProbe = auditRuntimeProbe.inspect()
        val notes = mutableListOf<String>()

        when {
            runtimeProbe.hits.isNotEmpty() -> {
                notes += "Controlled SELinux audit probes exposed policy or log-surface behavior that should not occur on a stock app path."
            }

            runtimeProbe.sideChannelHits.isNotEmpty() -> {
                notes += if (runtimeProbe.directProbeUsed) {
                    "A direct libselinux callback probe and app-visible auditd event logs both observed the same nonce-tagged AVC denial. Treat this as audit side-channel leakage, not direct root-process proof."
                } else {
                    "Readable auditd event logs exposed the controlled AVC denial probe. Treat this as audit side-channel leakage, not direct root-process proof."
                }
            }

            runtimeProbe.logcatChecked -> {
                notes += if (runtimeProbe.directProbeUsed) {
                    "A direct libselinux callback probe ran in-process, but readable auditd event logs did not expose the same nonce-tagged AVC denial or rewrite marker."
                } else {
                    "The auditd event buffer was readable, but no canonical audit rewrite marker or AVC leak surfaced."
                }
                notes += "AOSP does not guarantee that every device emits or exposes matching audit events to app-visible log readers, so this remains non-proving."
            }

            else -> {
                notes += runtimeProbe.failureReason
                    ?: "Recent auditd event logs were unavailable from the current app context."
            }
        }

        if (runtimeProbe.suspiciousActorHits.isNotEmpty()) {
            notes += "Readable AVC denials also referenced su-related actor strings such as comm/exe/path tokens. Treat this as supporting visibility evidence, not direct proof of a live root daemon."
        }

        if (residueHits.isNotEmpty()) {
            notes += "Readable auditpatch residue suggests logd audit output may be rewritten before apps inspect it."
        } else {
            notes += "No readable auditpatch residue surfaced under common module locations."
        }
        notes += "Absence of residue is not proof of absence because ordinary apps often cannot traverse /data/adb."

        val state = when {
            runtimeProbe.hits.isNotEmpty() -> SelinuxAuditIntegrityState.TAMPERED
            runtimeProbe.sideChannelHits.isNotEmpty() ||
                    runtimeProbe.suspiciousActorHits.isNotEmpty() -> SelinuxAuditIntegrityState.EXPOSED
            residueHits.isNotEmpty() -> SelinuxAuditIntegrityState.RESIDUE
            else -> SelinuxAuditIntegrityState.INCONCLUSIVE
        }

        return SelinuxAuditIntegrityAnalysis(
            state = state,
            residueHits = residueHits,
            runtimeHits = runtimeProbe.hits,
            sideChannelHits = runtimeProbe.sideChannelHits,
            suspiciousActorHits = runtimeProbe.suspiciousActorHits,
            logcatChecked = runtimeProbe.logcatChecked,
            directProbeUsed = runtimeProbe.directProbeUsed,
            notes = notes,
        )
    }

    private fun findAuditResidueHits(): List<SelinuxAuditEvidence> {
        return AUDITPATCH_RESIDUE_RULES.mapNotNull { rule ->
            val target = File(rule.path)
            runCatching {
                if (!target.exists()) {
                    return@mapNotNull null
                }
                SelinuxAuditEvidence(
                    label = rule.label,
                    value = rule.path,
                    detail = summarizeAuditResidue(target, rule),
                    strongSignal = rule.strongSignal,
                )
            }.getOrNull()
        }
    }

    private fun buildContextValidityMethod(
        result: SelinuxContextValidityProbeResult,
        source: EvidenceSource,
    ): SelinuxCheckResult {
        val status = when (result.state) {
            SelinuxContextValidityState.UNAVAILABLE ->
                SelinuxContextValidityProbe.BITPAIR_UNSUPPORTED

            SelinuxContextValidityState.CLEAN -> ""
            SelinuxContextValidityState.KSU_PRESENT ->
                SelinuxContextValidityProbe.BITPAIR_KSU_PRESENT

            SelinuxContextValidityState.AMBIGUOUS ->
                SelinuxContextValidityProbe.BITPAIR_AMBIGUOUS

            SelinuxContextValidityState.INCONSISTENT ->
                SelinuxContextValidityProbe.BITPAIR_SELF_TEST_FAILED
        }

        val detail = buildList {
            add("Carrier=${result.carrierContext ?: "<unreadable>"}\n")
            add("Carrier match=${if (result.carrierMatchesExpected) "yes" else "no"}\n")
            add("Carrier control=${when (result.carrierControlValid) {
                true -> "accepted"
                false -> "rejected"
                null -> "unavailable"
            }}\n")
            add("Negative control=${when (result.negativeControlRejected) {
                true -> "rejected"
                false -> "accepted"
                null -> "unavailable"
            }}\n")
            add("File control=${when (result.fileControlValid) {
                true -> "accepted"
                false -> "rejected"
                null -> "unavailable"
            }}\n")
            add("File negative control=${when (result.fileNegativeControlRejected) {
                true -> "rejected"
                false -> "accepted"
                null -> "unavailable"
            }}\n")
            add("Oracle trusted=${if (result.oracleControlsPassed) "yes" else "no"}\n")
            add("Repeatability=${if (result.ksuResultsStable) "stable" else "unstable"}\n")
            add("Evidence source=${source.label}\n")
            add(
                "Query=${
                    when (result.state) {
                        SelinuxContextValidityState.UNAVAILABLE -> "Unavailable"
                        else -> result.queryMethod.ifBlank { "raw selinuxfs write" }
                    }
                }\n"
            )
            when (result.state) {
                SelinuxContextValidityState.UNAVAILABLE ->
                    add("The app_zygote carrier snapshot was unavailable or untrusted.\n")

                SelinuxContextValidityState.CLEAN ->
                    add("KSU-specific contexts were not found by live policy.\n")

                SelinuxContextValidityState.KSU_PRESENT ->
                    add("Both KSU-specific contexts were found by live policy.\n")

                SelinuxContextValidityState.AMBIGUOUS ->
                    add("The two KSU-specific contexts split across live policy checks.\n")

                SelinuxContextValidityState.INCONSISTENT ->
                    add("Context validity oracle self-test or repeatability failed, so the KSU verdict was not trusted.\n")
            }
            result.notes.forEach { note ->
                add(note)
            }
        }.joinToString(" | ")

        return SelinuxCheckResult(
            method = SelinuxContextValidityProbe.METHOD_LABEL,
            status = status,
            isSecure = when (result.state) {
                SelinuxContextValidityState.UNAVAILABLE -> null
                SelinuxContextValidityState.CLEAN -> true
                SelinuxContextValidityState.KSU_PRESENT -> false
                SelinuxContextValidityState.AMBIGUOUS -> null
                SelinuxContextValidityState.INCONSISTENT -> null
            },
            permissionDenied = false,
            details = detail,
        )
    }

    private fun buildProcAttrCurrentMethod(
        result: SelinuxContextValidityProbeResult,
        source: EvidenceSource,
    ): SelinuxCheckResult {
        val outcomes = result.procAttrCurrentResults
        if (!result.procAttrCurrentProbeAttempted) {
            return SelinuxCheckResult(
                method = SelinuxProcAttrCurrentProbe.METHOD_LABEL,
                status = SelinuxProcAttrCurrentProbe.STATUS_UNSUPPORTED,
                isSecure = null,
                permissionDenied = false,
                details = listOfNotNull(
                    "Evidence source=${source.label}",
                    result.procAttrCurrentFailureReason ?: "Dedicated app_zygote attr/current write probe skipped.",
                ).joinToString(" | "),
            )
        }
        if (outcomes.isEmpty()) {
            return SelinuxCheckResult(
                method = SelinuxProcAttrCurrentProbe.METHOD_LABEL,
                status = SelinuxProcAttrCurrentProbe.STATUS_UNSUPPORTED,
                isSecure = null,
                permissionDenied = false,
                details = listOfNotNull(
                    "Evidence source=${source.label}",
                    result.procAttrCurrentFailureReason ?: "Dedicated app_zygote attr/current write probe returned no results.",
                ).joinToString(" | "),
            )
        }

        val detected = outcomes.filter(SelinuxProcAttrCurrentResult::detected)
        val clean = outcomes.all {
            it.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL
        }
        val status = when {
            detected.isNotEmpty() -> "Detected: ${detected.joinToString { it.label }}"
            clean -> SelinuxProcAttrCurrentProbe.STATUS_CLEAN
            else -> SelinuxProcAttrCurrentProbe.STATUS_UNSUPPORTED
        }
        val detail = listOf(
            "Evidence source=${source.label}",
            outcomes.joinToString(" | ") { outcome ->
                "${outcome.label}=${outcome.outcomeClass} target=${outcome.targetContext} raw=${outcome.rawMessage}"
            },
        ).joinToString(" | ")

        return SelinuxCheckResult(
            method = SelinuxProcAttrCurrentProbe.METHOD_LABEL,
            status = status,
            isSecure = when {
                detected.isNotEmpty() -> false
                clean -> true
                else -> null
            },
            permissionDenied = false,
            details = detail,
        )
    }

    internal fun buildDirtyPolicyMethods(
        result: SelinuxContextValidityProbeResult,
    ): List<SelinuxCheckResult> = buildDirtyPolicyMethods(result, EvidenceSource.DEDICATED_CARRIER)

    private fun buildDirtyPolicyMethods(
        result: SelinuxContextValidityProbeResult,
        source: EvidenceSource,
    ): List<SelinuxCheckResult> {
        val oracleTrusted = isDirtyPolicyOracleTrusted(result)
        return listOf(
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: system_server execmem",
                allowed = result.dirtyPolicySystemServerExecmemAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: system_server -> system_server:process execmem. This should stay denied on stock policy because executable system_server memory is supporting dirty-policy evidence.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: fsck_untrusted sys_admin",
                allowed = result.dirtyPolicyFsckSysAdminAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: fsck_untrusted -> fsck_untrusted:capability sys_admin. This should stay denied on stock policy because it represents a DirtySepolicy neverallow-style violation.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: shell -> su transition",
                allowed = result.dirtyPolicyShellSuTransitionAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: shell -> su:process transition. This is only evaluated for confirmed user builds because stock user builds should not expose an AOSP su transition path.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: adbd -> adbroot binder",
                allowed = result.dirtyPolicyAdbdAdbrootBinderCallAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: adbd -> adbroot:binder call. This should stay denied on stock policy because it is supporting adb-root dirty-policy evidence.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: untrusted_app -> magisk binder",
                allowed = result.dirtyPolicyMagiskBinderCallAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: untrusted_app -> magisk:binder call. This should stay denied on stock policy because ordinary apps should not talk to a Magisk domain over binder.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: untrusted_app -> ksu_file read",
                allowed = result.dirtyPolicyKsuFileReadAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: untrusted_app -> ksu_file:file read. This should stay denied on stock policy because ordinary apps should not read KernelSU-labeled files.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: untrusted_app -> lsposed_file read",
                allowed = result.dirtyPolicyLsposedFileReadAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: untrusted_app -> lsposed_file:file read. This should stay denied on stock policy because ordinary apps should not read LSPosed-labeled files.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: untrusted_app -> xposed_data read",
                allowed = result.dirtyPolicyXposedDataFileReadAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: untrusted_app -> xposed_data:file read. This should stay denied on stock policy because ordinary apps should not read Xposed data directly.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
            dirtyPolicyRuleMethod(
                label = "Dirty sepolicy rule: zygote -> adb_data_file search",
                allowed = result.dirtyPolicyZygoteAdbDataSearchAllowed.takeIf { oracleTrusted },
                detail = "Observed edge: zygote -> adb_data_file:dir search. This should stay denied on stock policy because zygote should not traverse adb data directories.",
                failureReason = result.dirtyPolicyFailureReason,
                source = source,
            ),
        )
    }

    internal fun isDirtyPolicyOracleTrusted(
        result: SelinuxContextValidityProbeResult,
    ): Boolean {
        return result.dirtyPolicyAvailable &&
            result.dirtyPolicyProbeAttempted &&
            result.dirtyPolicyCarrierMatchesExpected &&
            result.dirtyPolicyControlsPassed &&
            result.dirtyPolicyStable &&
            result.dirtyPolicyAccessControlAllowed == true &&
            result.dirtyPolicyNegativeControlRejected == true
    }

    private fun dirtyPolicyRuleMethod(
        label: String,
        allowed: Boolean?,
        detail: String,
        failureReason: String?,
        source: EvidenceSource,
    ): SelinuxCheckResult {
        val status = when (allowed) {
            true -> "Allowed"
            false -> "Denied"
            null -> "Unavailable"
        }
        return SelinuxCheckResult(
            method = label,
            status = status,
            isSecure = when (allowed) {
                true -> false
                false -> true
                null -> null
            },
            permissionDenied = false,
            details = listOfNotNull(
                "Evidence source=${source.label}",
                when (allowed) {
                    true -> "$detail The access oracle reported this edge as allowed."
                    false -> "$detail The access oracle reported this edge as denied."
                    null -> "$detail The access oracle could not produce a verdict for this edge."
                },
                failureReason?.takeIf { allowed == null }?.let { "Reason: $it" },
            ).joinToString(" | "),
        )
    }

    private fun summarizeAuditResidue(
        target: File,
        rule: AuditResidueRule,
    ): String {
        val contentSummary = if (target.isFile && target.canRead()) {
            runCatching {
                target.readText()
                    .replace("\n", " | ")
                    .replace("\r", "")
                    .trimToPreview()
            }.getOrNull()
        } else {
            null
        }
        return contentSummary ?: rule.detail
    }

    private fun readPolicyVersion(): Int? {
        return try {
            val file = File(SELINUX_POLICY_VERSION_PATH)
            if (file.exists() && file.canRead()) {
                file.readText().trim().toIntOrNull()
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun countSecurityClasses(): Pair<Int, List<String>> {
        return try {
            val classDir = File(SELINUX_CLASS_PATH)
            if (classDir.exists() && classDir.isDirectory) {
                val classes = classDir.listFiles()
                    ?.filter { it.isDirectory }
                    ?.map { it.name }
                    .orEmpty()
                classes.size to classes
            } else {
                0 to emptyList()
            }
        } catch (_: Exception) {
            0 to emptyList()
        }
    }

    private fun readProcessContext(): String? {
        return try {
            val file = File(PROC_ATTR_PATH)
            if (file.exists() && file.canRead()) {
                file.readText().trim().replace("\u0000", "")
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun checkPermissiveDomains(processContext: String?): List<String> {
        if (processContext.isNullOrBlank()) {
            return emptyList()
        }
        return if (processContext.contains("permissive", ignoreCase = true)) {
            listOf(processContext.split(":").getOrNull(2) ?: "unknown")
        } else {
            emptyList()
        }
    }

    private fun checkSelinuxFilesystem(): SelinuxCheckResult {
        return try {
            val mount = File(SELINUX_MOUNT_PATH)
            val policy = File(SELINUX_POLICY_PATH)
            val enforce = File(SELINUX_STATUS_PATH)
            when {
                !mount.exists() -> SelinuxCheckResult(
                    method = METHOD_FILESYSTEM,
                    status = FILESYSTEM_NOT_MOUNTED,
                    isSecure = false,
                    permissionDenied = false,
                    details = "/sys/fs/selinux does not exist",
                )

                policy.exists() && enforce.exists() -> SelinuxCheckResult(
                    method = METHOD_FILESYSTEM,
                    status = FILESYSTEM_ACTIVE,
                    isSecure = true,
                    permissionDenied = false,
                    details = "SELinux filesystem mounted with policy nodes",
                )

                else -> SelinuxCheckResult(
                    method = METHOD_FILESYSTEM,
                    status = FILESYSTEM_MOUNTED,
                    isSecure = true,
                    permissionDenied = false,
                    details = "SELinux filesystem present",
                )
            }
        } catch (throwable: Throwable) {
            SelinuxCheckResult(
                method = METHOD_FILESYSTEM,
                status = "Error",
                isSecure = null,
                permissionDenied = false,
                details = throwable.message ?: "Filesystem check failed",
            )
        }
    }

    private fun checkViaSysfs(): SelinuxCheckResult {
        return try {
            val enforceFile = File(SELINUX_STATUS_PATH)
            when {
                enforceFile.exists() && enforceFile.canRead() -> {
                    when (enforceFile.readText().trim()) {
                        "1" -> SelinuxCheckResult(
                            method = METHOD_SYSFS,
                            status = SELINUX_ENFORCING,
                            isSecure = true,
                            permissionDenied = false,
                            details = "/sys/fs/selinux/enforce = 1",
                        )

                        "0" -> SelinuxCheckResult(
                            method = METHOD_SYSFS,
                            status = SELINUX_PERMISSIVE,
                            isSecure = false,
                            permissionDenied = false,
                            details = "/sys/fs/selinux/enforce = 0",
                        )

                        else -> SelinuxCheckResult(
                            method = METHOD_SYSFS,
                            status = "Unknown",
                            isSecure = null,
                            permissionDenied = false,
                            details = "Unexpected sysfs value",
                        )
                    }
                }

                enforceFile.exists() && !enforceFile.canRead() -> SelinuxCheckResult(
                    method = METHOD_SYSFS,
                    status = BLOCKED_ENFORCING,
                    isSecure = true,
                    permissionDenied = true,
                    details = "enforce file present but unreadable",
                )

                else -> SelinuxCheckResult(
                    method = METHOD_SYSFS,
                    status = "Not found",
                    isSecure = null,
                    permissionDenied = false,
                    details = "enforce file does not exist",
                )
            }
        } catch (securityException: SecurityException) {
            SelinuxCheckResult(
                method = METHOD_SYSFS,
                status = BLOCKED_ENFORCING,
                isSecure = true,
                permissionDenied = true,
                details = "Access blocked by SELinux policy",
            )
        } catch (throwable: Throwable) {
            if (throwable.message.isPermissionDenied()) {
                SelinuxCheckResult(
                    method = METHOD_SYSFS,
                    status = BLOCKED_ENFORCING,
                    isSecure = true,
                    permissionDenied = true,
                    details = "Access blocked by SELinux policy",
                )
            } else {
                SelinuxCheckResult(
                    method = METHOD_SYSFS,
                    status = "Error",
                    isSecure = null,
                    permissionDenied = false,
                    details = throwable.message ?: "sysfs check failed",
                )
            }
        }
    }

    private fun checkViaGetenforce(): SelinuxCheckResult {
        var process: Process? = null
        return try {
            process = ProcessBuilder("getenforce")
                .redirectErrorStream(false)
                .start()

            val stdout = process.inputStream.bufferedReader().use { it.readText().trim() }
            val stderr = process.errorStream.bufferedReader().use { it.readText().trim() }
            val completed = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                return SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = "Timeout",
                    isSecure = null,
                    permissionDenied = false,
                    details = "Command timed out after ${PROCESS_TIMEOUT_SECONDS}s",
                )
            }

            when {
                stdout.equals(SELINUX_ENFORCING, ignoreCase = true) -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = SELINUX_ENFORCING,
                    isSecure = true,
                    permissionDenied = false,
                    details = "Command returned Enforcing",
                )

                stdout.equals(SELINUX_PERMISSIVE, ignoreCase = true) -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = SELINUX_PERMISSIVE,
                    isSecure = false,
                    permissionDenied = false,
                    details = "Command returned Permissive",
                )

                stdout.equals(SELINUX_DISABLED, ignoreCase = true) -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = SELINUX_DISABLED,
                    isSecure = false,
                    permissionDenied = false,
                    details = "Command returned Disabled",
                )

                stderr.isPermissionDenied() -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = BLOCKED_ENFORCING,
                    isSecure = true,
                    permissionDenied = true,
                    details = "Command blocked by SELinux policy",
                )

                stderr.isNotBlank() -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = "Error",
                    isSecure = null,
                    permissionDenied = false,
                    details = "stderr: $stderr",
                )

                stdout.isBlank() -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = "No output",
                    isSecure = null,
                    permissionDenied = false,
                    details = "Command returned empty",
                )

                else -> SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = "Unknown",
                    isSecure = null,
                    permissionDenied = false,
                    details = "Unexpected: $stdout",
                )
            }
        } catch (throwable: Throwable) {
            if (throwable.message.isPermissionDenied()) {
                SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = BLOCKED_ENFORCING,
                    isSecure = true,
                    permissionDenied = true,
                    details = "Execution blocked by SELinux",
                )
            } else {
                SelinuxCheckResult(
                    method = METHOD_GETENFORCE,
                    status = "Failed",
                    isSecure = null,
                    permissionDenied = false,
                    details = throwable.message ?: "getenforce failed",
                )
            }
        } finally {
            process?.destroy()
        }
    }

    private fun checkViaProcAttr(): SelinuxCheckResult {
        return try {
            val procAttrFile = File(PROC_ATTR_PATH)
            if (procAttrFile.exists() && procAttrFile.canRead()) {
                val context = procAttrFile.readText().trim().replace("\u0000", "")
                if (context.isBlank()) {
                    SelinuxCheckResult(
                        method = METHOD_PROC_ATTR,
                        status = "Empty",
                        isSecure = null,
                        permissionDenied = false,
                        details = "Context file empty",
                    )
                } else {
                    val type = context.split(":").getOrNull(2) ?: "unknown"
                    when {
                        type == "untrusted_app" || type.contains(
                            "app",
                            ignoreCase = true
                        ) -> SelinuxCheckResult(
                            method = METHOD_PROC_ATTR,
                            status = SELINUX_ENFORCING,
                            isSecure = true,
                            permissionDenied = false,
                            details = "Context: $context (confined to $type)",
                        )

                        type == "kernel" || type == "init" -> SelinuxCheckResult(
                            method = METHOD_PROC_ATTR,
                            status = "System context",
                            isSecure = true,
                            permissionDenied = false,
                            details = "Context: $context",
                        )

                        context.contains(":") -> SelinuxCheckResult(
                            method = METHOD_PROC_ATTR,
                            status = SELINUX_ENFORCING,
                            isSecure = true,
                            permissionDenied = false,
                            details = "Context: $context",
                        )

                        else -> SelinuxCheckResult(
                            method = METHOD_PROC_ATTR,
                            status = "Unknown context",
                            isSecure = null,
                            permissionDenied = false,
                            details = "Raw: $context",
                        )
                    }
                }
            } else {
                SelinuxCheckResult(
                    method = METHOD_PROC_ATTR,
                    status = "Not readable",
                    isSecure = null,
                    permissionDenied = !procAttrFile.exists(),
                    details = if (procAttrFile.exists()) "Access denied" else "File not found",
                )
            }
        } catch (securityException: SecurityException) {
            SelinuxCheckResult(
                method = METHOD_PROC_ATTR,
                status = "Blocked",
                isSecure = null,
                permissionDenied = true,
                details = securityException.message ?: "SecurityException",
            )
        } catch (throwable: Throwable) {
            SelinuxCheckResult(
                method = METHOD_PROC_ATTR,
                status = "Error",
                isSecure = null,
                permissionDenied = false,
                details = throwable.message ?: "proc attr check failed",
            )
        }
    }

    private fun determineStatusWithParadoxLogic(
        results: List<SelinuxCheckResult>,
    ): StatusResolution {
        val filesystemActive = results.any {
            it.method == METHOD_FILESYSTEM && (it.status == FILESYSTEM_ACTIVE || it.status == FILESYSTEM_MOUNTED)
        }

        results.forEach { result ->
            if (result.status == SELINUX_PERMISSIVE) {
                return StatusResolution(
                    SelinuxMode.PERMISSIVE,
                    SELINUX_PERMISSIVE,
                    paradoxDetected = false
                )
            }
            if (result.status == SELINUX_DISABLED || result.status == FILESYSTEM_NOT_MOUNTED) {
                return StatusResolution(
                    SelinuxMode.DISABLED,
                    SELINUX_DISABLED,
                    paradoxDetected = false
                )
            }
        }

        if (results.any { it.status == SELINUX_ENFORCING }) {
            return StatusResolution(
                SelinuxMode.ENFORCING,
                SELINUX_ENFORCING,
                paradoxDetected = false
            )
        }

        val hasPermissionDenied = results.any { it.permissionDenied }
        if (hasPermissionDenied && filesystemActive) {
            return StatusResolution(
                SelinuxMode.ENFORCING,
                "Enforcing (paradox)",
                paradoxDetected = true
            )
        }

        if (filesystemActive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return StatusResolution(
                SelinuxMode.ENFORCING,
                "Enforcing (default)",
                paradoxDetected = false
            )
        }

        return StatusResolution(SelinuxMode.UNKNOWN, "Unknown", paradoxDetected = false)
    }

    private fun String?.isPermissionDenied(): Boolean {
        return this?.contains("Permission denied", ignoreCase = true) == true ||
                this?.contains("EACCES", ignoreCase = true) == true
    }

    private fun String.trimToPreview(
        maxLength: Int = 180,
    ): String {
        val normalized = replace(Regex("\\s+"), " ").trim()
        return if (normalized.length <= maxLength) {
            normalized
        } else {
            normalized.take(maxLength - 3).trimEnd() + "..."
        }
    }

    private data class StatusResolution(
        val mode: SelinuxMode,
        val label: String,
        val paradoxDetected: Boolean,
    )

    private enum class EvidenceSource(
        val label: String,
    ) {
        DEDICATED_CARRIER("dedicated app_zygote carrier"),
        LOCAL_FALLBACK("local native fallback"),
    }

    private data class AuditResidueRule(
        val path: String,
        val label: String,
        val detail: String,
        val strongSignal: Boolean = false,
    )

    companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 5L

        private const val SELINUX_ENFORCING = "Enforcing"
        private const val SELINUX_PERMISSIVE = "Permissive"
        private const val SELINUX_DISABLED = "Disabled"
        private const val BLOCKED_ENFORCING = "Blocked (Enforcing)"

        private const val METHOD_FILESYSTEM = "filesystem"
        private const val METHOD_SYSFS = "sysfs"
        private const val METHOD_GETENFORCE = "getenforce"
        private const val METHOD_PROC_ATTR = "proc/self/attr"

        private const val FILESYSTEM_NOT_MOUNTED = "Not mounted"
        private const val FILESYSTEM_ACTIVE = "Active"
        private const val FILESYSTEM_MOUNTED = "Mounted"

        private const val SELINUX_STATUS_PATH = "/sys/fs/selinux/enforce"
        private const val SELINUX_MOUNT_PATH = "/sys/fs/selinux"
        private const val SELINUX_POLICY_PATH = "/sys/fs/selinux/policy"
        private const val SELINUX_POLICY_VERSION_PATH = "/sys/fs/selinux/policyvers"
        private const val SELINUX_CLASS_PATH = "/sys/fs/selinux/class"
        private const val PROC_ATTR_PATH = "/proc/self/attr/current"

        private const val MIN_EXPECTED_POLICY_VERSION = 28

        private val DANGEROUS_TYPES = listOf(
            "su",
            "supersu",
            "magisk",
            "permissive",
            "unconfined",
            "shell",
        )

        private val EXPECTED_CLASSES = listOf(
            "file",
            "dir",
            "process",
            "capability",
            "socket",
            "binder",
        )

        private val AUDITPATCH_RESIDUE_RULES = listOf(
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch",
                label = "Module directory",
                detail = "Common Magisk or Zygisk module path for ZN-AuditPatch.",
                strongSignal = true,
            ),
            AuditResidueRule(
                path = "/data/adb/modules_update/auditpatch",
                label = "Pending module update",
                detail = "Auditpatch module staged for activation.",
                strongSignal = true,
            ),
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch/module.prop",
                label = "Module metadata",
                detail = "Module metadata for auditpatch.",
                strongSignal = true,
            ),
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch/zn_modules.txt",
                label = "ZN target list",
                detail = "ZN target list that points the module at logd.",
                strongSignal = true,
            ),
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch/service.sh",
                label = "Service script",
                detail = "Boot script that restarts logd after boot.",
            ),
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch/sepolicy.rule",
                label = "SEPolicy patch",
                detail = "Policy rule shipped with auditpatch residue.",
            ),
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch/lib/arm64/libauditpatch.so",
                label = "ARM64 native hook",
                detail = "Native hook library injected into logd.",
                strongSignal = true,
            ),
            AuditResidueRule(
                path = "/data/adb/modules/auditpatch/lib/x64/libauditpatch.so",
                label = "x64 native hook",
                detail = "Native hook library injected into logd.",
                strongSignal = true,
            ),
        )
    }
}
