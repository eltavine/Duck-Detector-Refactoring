/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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
import android.os.SystemClock
import com.eltavine.duckdetector.core.platform.PathState
import com.eltavine.duckdetector.core.platform.PathStat
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbe
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValidityCarrierManager
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxAuditRuntimeProbe
import com.eltavine.duckdetector.features.selinux.data.probes.buildSelinuxHideTimingMethod
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxHideTimingNativeBridge
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditNote
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditNoteKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SelinuxRepository(
    context: Context? = null,
    private val auditRuntimeProbe: SelinuxAuditRuntimeProbe = SelinuxAuditRuntimeProbe(),
    private val contextValidityProbe: SelinuxContextValidityProbe = SelinuxContextValidityProbe(),
    private val contextValidityCarrierManager: SelinuxContextValidityCarrierManager =
        SelinuxContextValidityCarrierManager(context?.applicationContext),
) : DetectorScanner<SelinuxReport> {

    private val hideTimingProbe = SelinuxHideTimingNativeBridge()

    override suspend fun scan(): SelinuxReport = withContext(Dispatchers.IO) {
        try {
            scanInternal()
        } catch (throwable: Throwable) {
            SelinuxReport.failed(throwable.message ?: "SELinux scan failed.")
        }
    }

    private suspend fun scanInternal(): SelinuxReport {
        val scanStartedAt = SystemClock.elapsedRealtime()
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
        // Independent ordinary-app write timing channel, NOT the dedicated
        // app_zygote attr/current oracle. It never requires root privileges.
        methods += buildSelinuxHideTimingMethod(hideTimingProbe.collectSnapshot())

        val carrierSnapshot = contextValidityCarrierManager.collectSnapshot(scanStartedAt)
        val carrierResult = contextValidityProbe.interpret(carrierSnapshot)
        val contextValidityResult = carrierResult
        methods += buildContextValidityMethod(contextValidityResult)
        methods += buildPolicyloadSeqnoMethod(contextValidityResult)
        methods += buildProcAttrCurrentMethod(carrierResult, EvidenceSource.DEDICATED_CARRIER)
        methods += buildDirtyPolicyMethods(carrierSnapshot)
        methods += buildSidtabMethod(carrierSnapshot.sidtab)

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

    private fun analyzeAuditIntegrity(): SelinuxAuditIntegrityAnalysis {
        val residueObservable = AUDITPATCH_RESIDUE_RULES.none { rule ->
            PathStat.of(rule.path) == PathState.NOT_OBSERVABLE
        }
        val residueHits = findAuditResidueHits()
        val runtimeProbe = auditRuntimeProbe.inspect()
        val notes = mutableListOf<SelinuxAuditNote>()

        when {
            runtimeProbe.hits.isNotEmpty() -> {
                notes += SelinuxAuditNote(
                    SelinuxAuditNoteKind.PROBES_EXPOSED_TAMPERING,
                    "Controlled SELinux audit probes exposed policy or log-surface behavior that should not occur on a stock app path.",
                )
            }

            runtimeProbe.sideChannelHits.isNotEmpty() -> {
                notes += SelinuxAuditNote(
                    SelinuxAuditNoteKind.SIDE_CHANNEL_LEAK,
                    if (runtimeProbe.directProbeUsed) {
                        "A direct libselinux callback probe and app-visible auditd event logs both observed the same nonce-tagged AVC denial. Treat this as audit side-channel leakage, not direct root-process proof."
                    } else {
                        "Readable auditd event logs exposed the controlled AVC denial probe. Treat this as audit side-channel leakage, not direct root-process proof."
                    },
                )
            }

            runtimeProbe.logcatChecked -> {
                notes += if (runtimeProbe.directProbeUsed) {
                    SelinuxAuditNote(
                        SelinuxAuditNoteKind.DIRECT_PROBE_NOT_LEAKED,
                        "A direct libselinux callback probe ran in-process, but readable auditd event logs did not expose the same nonce-tagged AVC denial or rewrite marker.",
                    )
                } else {
                    SelinuxAuditNote(
                        SelinuxAuditNoteKind.EVENT_BUFFER_CLEAN,
                        "The auditd event buffer was readable, but no canonical audit rewrite marker or AVC leak surfaced.",
                    )
                }
                notes += SelinuxAuditNote(
                    SelinuxAuditNoteKind.EVENTS_NOT_GUARANTEED,
                    "AOSP does not guarantee that every device emits or exposes matching audit events to app-visible log readers, so this remains non-proving.",
                )
            }

            else -> {
                notes += SelinuxAuditNote(
                    SelinuxAuditNoteKind.EVENT_LOGS_UNAVAILABLE,
                    runtimeProbe.failureReason ?: "Recent auditd event logs were unavailable from the current app context.",
                )
            }
        }

        if (runtimeProbe.suspiciousActorHits.isNotEmpty()) {
            notes += SelinuxAuditNote(
                SelinuxAuditNoteKind.SU_ACTOR_REFERENCED,
                "Readable AVC denials also referenced su-related actor strings such as comm/exe/path tokens. Treat this as supporting visibility evidence, not direct proof of a live root daemon.",
            )
        }

        notes += when {
            residueHits.isNotEmpty() -> SelinuxAuditNote(
                SelinuxAuditNoteKind.RESIDUE_FOUND,
                "Readable auditpatch residue suggests logd audit output may be rewritten before apps inspect it.",
            )
            residueObservable -> SelinuxAuditNote(
                SelinuxAuditNoteKind.NO_RESIDUE,
                "No auditpatch residue exists under common module locations.",
            )
            else -> SelinuxAuditNote(
                SelinuxAuditNoteKind.RESIDUE_UNCHECKED,
                "Common auditpatch module locations could not be checked from this app.",
            )
        }
        notes += SelinuxAuditNote(
            SelinuxAuditNoteKind.ABSENCE_NOT_PROOF,
            "Absence of residue is not proof of absence because ordinary apps often cannot traverse /data/adb.",
        )

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
            residueObservable = residueObservable,
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
                if (PathStat.of(rule.path) != PathState.PRESENT) {
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

    private data class AuditResidueRule(
        val path: String,
        val label: String,
        val detail: String,
        val strongSignal: Boolean = false,
    )

    companion object {
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
