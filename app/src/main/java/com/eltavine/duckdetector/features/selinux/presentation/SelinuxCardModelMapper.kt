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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxCardModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxDetailRowModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxHeaderFactModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxImpactItemModel

class SelinuxCardModelMapper {

    fun map(report: SelinuxReport): SelinuxCardModel {
        return SelinuxCardModel(
            title = "SELinux",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            stateRows = buildStateRows(report),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            policyRows = buildPolicyRows(report.policyAnalysis),
            policyNotes = buildPolicyNotes(report.policyAnalysis),
            auditRows = buildAuditRows(report.auditIntegrity),
            auditNotes = buildAuditNotes(report.auditIntegrity),
            deviceRows = buildDeviceRows(report),
            references = buildReferences(),
        )
    }

    private fun buildSubtitle(report: SelinuxReport): String {
        return when (report.stage) {
            SelinuxStage.LOADING -> "sysfs + getenforce + proc attr + policy + audit"
            SelinuxStage.FAILED -> "local status probe failed"
            SelinuxStage.READY -> buildString {
                append("4 local checks")
                if (report.policyAnalysis != null) {
                    append(" + policy")
                }
                if (report.auditIntegrity != null) {
                    append(" + audit integrity + side-channel")
                }
            }
        }
    }

    private fun buildVerdict(report: SelinuxReport): String {
        return when (report.stage) {
            SelinuxStage.LOADING -> "Scanning SELinux state"
            SelinuxStage.FAILED -> "SELinux scan failed"
            SelinuxStage.READY -> when (report.mode) {
                SelinuxMode.ENFORCING -> when {
                    report.auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> "Enforcing with audit rewrite"
                    report.auditIntegrity?.state == SelinuxAuditIntegrityState.EXPOSED -> "Enforcing with audit exposure"
                    report.policyAnalysis?.weakness == SelinuxPolicyWeakness.SEVERE -> "Enforcing with weak policy"
                    report.auditIntegrity?.state == SelinuxAuditIntegrityState.RESIDUE -> "Enforcing with audit risk"
                    report.policyAnalysis?.weakness == SelinuxPolicyWeakness.MODERATE -> "Enforcing with policy drift"
                    report.policyAnalysis?.weakness == SelinuxPolicyWeakness.MINOR -> "Enforcing with minor drift"
                    else -> "Enforcing"
                }

                SelinuxMode.PERMISSIVE -> "Permissive"
                SelinuxMode.DISABLED -> "Disabled"
                SelinuxMode.UNKNOWN -> "Unknown"
            }
        }
    }

    private fun buildSummary(report: SelinuxReport): String {
        return when (report.stage) {
            SelinuxStage.LOADING ->
                "Checking sysfs, getenforce, and /proc/self/attr/current before deriving final mode with paradox logic."

            SelinuxStage.FAILED ->
                report.errorMessage
                    ?: "SELinux scan failed before the detector could assemble local evidence."

            SelinuxStage.READY -> when (report.mode) {
                SelinuxMode.ENFORCING -> {
                    val base = when (report.policyAnalysis?.weakness) {
                        SelinuxPolicyWeakness.SEVERE ->
                            "SELinux is enforcing, but the policy looks severely weakened or modified."

                        SelinuxPolicyWeakness.MODERATE ->
                            "SELinux is enforcing, but policy analysis found noticeable drift."

                        SelinuxPolicyWeakness.MINOR ->
                            "SELinux is enforcing and only minor policy drift surfaced."

                        SelinuxPolicyWeakness.NONE, null ->
                            "SELinux is enforcing and the visible policy surface looks internally consistent."
                    }
                    val extra = buildList {
                        if (report.paradoxDetected) {
                            add("Permission-denied probes also reinforced the enforcing verdict.")
                        }
                        when (report.auditIntegrity?.state) {
                            SelinuxAuditIntegrityState.TAMPERED ->
                                add("Recent audit or log markers suggest logd output is being rewritten before apps inspect it.")

                            SelinuxAuditIntegrityState.EXPOSED ->
                                add("Recent audit evidence exposed readable SELinux AVC denial lines, which indicates audit side-channel leakage rather than direct root-process proof.")

                            SelinuxAuditIntegrityState.RESIDUE ->
                                add("Readable auditpatch residue suggests the audit surface may be rewritten.")

                            SelinuxAuditIntegrityState.INCONCLUSIVE ->
                                add("Audit rewrite checks remained non-proving from the current app context.")

                            SelinuxAuditIntegrityState.CLEAR, null -> Unit
                        }
                    }
                    listOf(base).plus(extra).joinToString(" ")
                }

                SelinuxMode.PERMISSIVE ->
                    "SELinux still labels activity, but violations are logged instead of blocked."

                SelinuxMode.DISABLED ->
                    "Mandatory access control is off, so SELinux no longer constrains process behavior."

                SelinuxMode.UNKNOWN ->
                    "Local probes did not resolve a stable SELinux mode."
            }
        }
    }

    private fun buildHeaderFacts(report: SelinuxReport): List<SelinuxHeaderFactModel> {
        val policy = report.policyAnalysis
        return listOf(
            SelinuxHeaderFactModel(
                label = "Mode",
                value = report.resolvedStatusLabel,
                status = modeStatus(report.mode),
            ),
            SelinuxHeaderFactModel(
                label = "Policy",
                value = policyWeaknessLabel(policy?.weakness),
                status = policyWeaknessStatus(policy?.weakness),
            ),
            SelinuxHeaderFactModel(
                label = "Audit",
                value = auditIntegrityLabel(report.auditIntegrity),
                status = auditIntegrityStatus(report.auditIntegrity),
            ),
            SelinuxHeaderFactModel(
                label = "Context",
                value = report.contextType ?: "Unknown",
                status = when {
                    policy?.dangerousTypesFound?.isNotEmpty() == true -> DetectorStatus.danger()
                    report.contextType != null -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
        )
    }

    private fun buildStateRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
        val detectionPath = when {
            report.paradoxDetected -> "Paradox logic"
            report.methods.any {
                it.status.equals(
                    "Enforcing",
                    ignoreCase = true
                )
            } -> "Direct confirmation"

            else -> "Fallback inference"
        }
        return listOf(
            SelinuxDetailRowModel(
                label = "Mode",
                value = report.resolvedStatusLabel,
                status = modeStatus(report.mode),
            ),
            SelinuxDetailRowModel(
                label = "Policy enforced",
                value = when (report.mode) {
                    SelinuxMode.ENFORCING -> "Yes"
                    SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> "No"
                    SelinuxMode.UNKNOWN -> "Unknown"
                },
                status = modeStatus(report.mode),
            ),
            SelinuxDetailRowModel(
                label = "MAC active",
                value = when (report.mode) {
                    SelinuxMode.ENFORCING -> "Yes"
                    SelinuxMode.PERMISSIVE -> "Logging only"
                    SelinuxMode.DISABLED -> "No"
                    SelinuxMode.UNKNOWN -> "Unknown"
                },
                status = modeStatus(report.mode),
            ),
            SelinuxDetailRowModel(
                label = "Filesystem",
                value = if (report.filesystemMounted) "Mounted" else "Missing",
                status = if (report.filesystemMounted) DetectorStatus.allClear() else DetectorStatus.danger(),
            ),
            SelinuxDetailRowModel(
                label = "Detection path",
                value = detectionPath,
                status = DetectorStatus.allClear(),
            ),
            SelinuxDetailRowModel(
                label = "Process context",
                value = report.contextType ?: "Unknown",
                status = if (report.processContext != null) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
                detail = report.processContext,
            ),
        )
    }

    private fun buildImpactItems(report: SelinuxReport): List<SelinuxImpactItemModel> {
        if (report.stage != SelinuxStage.READY) {
            return when (report.stage) {
                SelinuxStage.LOADING -> listOf(
                    SelinuxImpactItemModel(
                        text = "Gathering local status evidence.",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                    ),
                )

                SelinuxStage.FAILED -> listOf(
                    SelinuxImpactItemModel(
                        text = report.errorMessage ?: "Scan failed.",
                        status = DetectorStatus.info(InfoKind.ERROR),
                    ),
                )

                SelinuxStage.READY -> emptyList()
            }
        }

        val items = mutableListOf<SelinuxImpactItemModel>()
        when (report.mode) {
            SelinuxMode.ENFORCING -> {
                items += SelinuxImpactItemModel(
                    "Mandatory access control is active.",
                    DetectorStatus.allClear()
                )
                items += SelinuxImpactItemModel(
                    "Policy violations should be blocked and logged.",
                    DetectorStatus.allClear()
                )
                if (report.paradoxDetected) {
                    items += SelinuxImpactItemModel(
                        "Permission-denied probes acted as positive evidence for enforcing mode.",
                        DetectorStatus.allClear(),
                    )
                }
                when (report.auditIntegrity?.state) {
                    SelinuxAuditIntegrityState.TAMPERED -> items += SelinuxImpactItemModel(
                        "Audit logs appear rewritten, so SELinux denials may look normal even when privileged contexts are present.",
                        DetectorStatus.danger(),
                    )

                    SelinuxAuditIntegrityState.EXPOSED -> items += SelinuxImpactItemModel(
                        "Readable SELinux AVC denial lines leaked through the audit surface. This is audit-surface exposure, not direct proof of a root daemon.",
                        DetectorStatus.warning(),
                    )

                    SelinuxAuditIntegrityState.RESIDUE -> items += SelinuxImpactItemModel(
                        "Readable auditpatch residue suggests audit denials could be relabeled or masked.",
                        DetectorStatus.warning(),
                    )

                    SelinuxAuditIntegrityState.INCONCLUSIVE -> items += SelinuxImpactItemModel(
                        "Audit rewrite checks were partially unavailable from this app context.",
                        DetectorStatus.info(InfoKind.SUPPORT),
                    )

                    SelinuxAuditIntegrityState.CLEAR, null -> Unit
                }
                when (report.policyAnalysis?.weakness) {
                    SelinuxPolicyWeakness.MODERATE -> items += SelinuxImpactItemModel(
                        "Policy drift may allow some restrictions to be bypassed.",
                        DetectorStatus.warning(),
                    )

                    SelinuxPolicyWeakness.SEVERE -> items += SelinuxImpactItemModel(
                        "Policy looks heavily weakened, so enforcement may be ineffective.",
                        DetectorStatus.danger(),
                    )

                    else -> Unit
                }
            }

            SelinuxMode.PERMISSIVE -> {
                items += SelinuxImpactItemModel(
                    "Violations are logged but not blocked.",
                    DetectorStatus.danger(),
                )
                items += SelinuxImpactItemModel(
                    "Security-sensitive apps and integrity checks may fail.",
                    DetectorStatus.danger(),
                )
            }

            SelinuxMode.DISABLED -> {
                items += SelinuxImpactItemModel(
                    "Mandatory access control is completely disabled.",
                    DetectorStatus.danger(),
                )
                items += SelinuxImpactItemModel(
                    "The device is likely heavily modified or compromised.",
                    DetectorStatus.danger(),
                )
            }

            SelinuxMode.UNKNOWN -> {
                items += SelinuxImpactItemModel(
                    "Local probes were inconclusive.",
                    DetectorStatus.info(InfoKind.ERROR),
                )
            }
        }
        return items
    }

    private fun buildMethodRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
        return report.methods.map { result ->
            SelinuxDetailRowModel(
                label = result.method,
                value = result.status,
                status = methodStatus(result),
                detail = result.details,
            )
        }
    }

    private fun buildPolicyRows(policy: SelinuxPolicyAnalysis?): List<SelinuxDetailRowModel> {
        if (policy == null) {
            return emptyList()
        }
        return listOf(
            SelinuxDetailRowModel(
                label = "Strength",
                value = policyWeaknessLabel(policy.weakness),
                status = policyWeaknessStatus(policy.weakness),
            ),
            SelinuxDetailRowModel(
                label = "Policy version",
                value = policy.policyVersion?.toString() ?: "Unreadable",
                status = when {
                    policy.policyVersion == null -> DetectorStatus.info(InfoKind.SUPPORT)
                    policy.policyVersionOk -> DetectorStatus.allClear()
                    else -> DetectorStatus.warning()
                },
            ),
            SelinuxDetailRowModel(
                label = "Security classes",
                value = policyClassValue(policy),
                status = policyClassStatus(policy),
                detail = if (policy.classCount == 0 && policy.foundClasses.isEmpty()) {
                    "Class directory unreadable from the current app context."
                } else if (policy.missingClasses.isNotEmpty()) {
                    "Missing: ${policy.missingClasses.joinToString()}"
                } else {
                    null
                },
            ),
            SelinuxDetailRowModel(
                label = "Process context",
                value = policy.contextType ?: "Unknown",
                status = if (policy.dangerousTypesFound.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
                detail = policy.processContext,
            ),
            SelinuxDetailRowModel(
                label = "Dangerous types",
                value = if (policy.dangerousTypesFound.isEmpty()) "None" else policy.dangerousTypesFound.joinToString(),
                status = if (policy.dangerousTypesFound.isEmpty()) DetectorStatus.allClear() else DetectorStatus.danger(),
            ),
            SelinuxDetailRowModel(
                label = "Permissive domains",
                value = if (policy.permissiveDomains.isEmpty()) "None" else policy.permissiveDomains.joinToString(),
                status = if (policy.permissiveDomains.isEmpty()) DetectorStatus.allClear() else DetectorStatus.warning(),
            ),
        )
    }

    private fun buildPolicyNotes(policy: SelinuxPolicyAnalysis?): List<SelinuxImpactItemModel> {
        return policy?.details?.map { detail ->
            SelinuxImpactItemModel(
                text = detail,
                status = when {
                    detail.contains("below minimum", ignoreCase = true) -> DetectorStatus.warning()
                    detail.contains("missing", ignoreCase = true) -> DetectorStatus.warning()
                    detail.contains("dangerous", ignoreCase = true) -> DetectorStatus.danger()
                    detail.contains("permissive", ignoreCase = true) -> DetectorStatus.warning()
                    detail.contains("normal", ignoreCase = true) -> DetectorStatus.allClear()
                    detail.contains("meets minimum", ignoreCase = true) -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            )
        }.orEmpty()
    }

    private fun buildAuditRows(analysis: SelinuxAuditIntegrityAnalysis?): List<SelinuxDetailRowModel> {
        if (analysis == null) {
            return emptyList()
        }

        val rows = mutableListOf(
            SelinuxDetailRowModel(
                label = "Surface",
                value = auditIntegrityLabel(analysis),
                status = auditIntegrityStatus(analysis),
            ),
            SelinuxDetailRowModel(
                label = "Runtime markers",
                value = when {
                    analysis.runtimeHits.isNotEmpty() -> "${analysis.runtimeHits.size} hit(s)"
                    analysis.logcatChecked -> "Not observed"
                    else -> "Unavailable"
                },
                status = when {
                    analysis.runtimeHits.isNotEmpty() -> DetectorStatus.danger()
                    analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = when {
                    analysis.runtimeHits.isNotEmpty() ->
                        "Known auditpatch runtime markers surfaced in recent auditd event logs."

                    analysis.logcatChecked ->
                        "Recent auditd event logs were readable, but absence of markers is not proof of a clean audit surface."

                    else ->
                        "The current app could not read recent auditd event logs."
                },
            ),
            SelinuxDetailRowModel(
                label = "AVC side-channel",
                value = when {
                    analysis.sideChannelHits.isNotEmpty() -> "${analysis.sideChannelHits.size} hit(s)"
                    analysis.logcatChecked -> "Not observed"
                    else -> "Unavailable"
                },
                status = when {
                    analysis.sideChannelHits.isNotEmpty() -> DetectorStatus.warning()
                    analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = when {
                    analysis.sideChannelHits.isNotEmpty() ->
                        "Readable auditd event logs exposed the same nonce-tagged controlled AVC denial seen by the direct libselinux callback probe."

                    analysis.directProbeUsed && analysis.logcatChecked ->
                        "No matching nonce-tagged controlled AVC denial surfaced in the readable auditd event window."

                    analysis.logcatChecked ->
                        "No matching controlled AVC denial surfaced in the readable auditd event window, but absence is not proof."

                    else ->
                        "The current app could not read recent auditd event logs."
                },
            ),
            SelinuxDetailRowModel(
                label = "su-related AVC",
                value = when {
                    analysis.suspiciousActorHits.isNotEmpty() -> "${analysis.suspiciousActorHits.size} hit(s)"
                    analysis.logcatChecked -> "Not observed"
                    else -> "Unavailable"
                },
                status = when {
                    analysis.suspiciousActorHits.isNotEmpty() -> DetectorStatus.warning()
                    analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
                detail = when {
                    analysis.suspiciousActorHits.isNotEmpty() ->
                        "Readable AVC denials referenced su/magisk/ksud-related actor strings in comm, exe, path, or name fields."

                    analysis.logcatChecked ->
                        "No su-related actor string surfaced in the readable canonical AVC window."

                    else ->
                        "The current app could not read recent auditd event logs."
                },
            ),
            SelinuxDetailRowModel(
                label = "Residue paths",
                value = if (analysis.residueHits.isNotEmpty()) "${analysis.residueHits.size} hit(s)" else "None",
                status = when {
                    analysis.residueHits.any { it.strongSignal } -> DetectorStatus.warning()
                    analysis.residueHits.isNotEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.allClear()
                },
                detail = if (analysis.residueHits.isNotEmpty()) {
                    "Readable module residue matched common ZN-AuditPatch locations."
                } else {
                    "No readable auditpatch residue surfaced under common module paths."
                },
            ),
        )

        analysis.runtimeHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = hit.value,
                status = if (hit.strongSignal) DetectorStatus.danger() else DetectorStatus.warning(),
                detail = hit.detail,
            )
        }
        analysis.sideChannelHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = hit.value,
                status = DetectorStatus.warning(),
                detail = hit.detail,
            )
        }
        analysis.suspiciousActorHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = hit.value,
                status = DetectorStatus.warning(),
                detail = hit.detail,
            )
        }
        analysis.residueHits.forEach { hit ->
            rows += SelinuxDetailRowModel(
                label = hit.label,
                value = "Readable",
                status = if (hit.strongSignal) DetectorStatus.warning() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
                detail = listOfNotNull(hit.value, hit.detail).joinToString(" | "),
            )
        }
        return rows
    }

    private fun buildAuditNotes(analysis: SelinuxAuditIntegrityAnalysis?): List<SelinuxImpactItemModel> {
        return analysis?.notes?.map { note ->
            SelinuxImpactItemModel(
                text = note,
                status = when {
                    note.contains("rewrite markers", ignoreCase = true) -> DetectorStatus.danger()
                    note.contains("side-channel", ignoreCase = true) -> DetectorStatus.warning()
                    note.contains("su-related actor", ignoreCase = true) -> DetectorStatus.warning()
                    note.contains(
                        "Readable auditpatch residue",
                        ignoreCase = true
                    ) -> DetectorStatus.warning()

                    note.contains("did not expose", ignoreCase = true) -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            )
        }.orEmpty()
    }

    private fun buildDeviceRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
        return listOf(
            SelinuxDetailRowModel(
                label = "Android",
                value = if (report.androidVersion.isNotBlank()) report.androidVersion else "Unknown",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            SelinuxDetailRowModel(
                label = "API level",
                value = if (report.apiLevel > 0) report.apiLevel.toString() else "Unknown",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
            SelinuxDetailRowModel(
                label = "Required since",
                value = "Android 5.0 (API 21)",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )
    }

    private fun buildReferences(): List<String> {
        return listOf(
            "SELinux paradox: permission denied can prove enforcing mode.",
            "Enforcing mode blocks disallowed actions instead of only logging them.",
            "Production Android devices are expected to run enforcing SELinux.",
            "Audit or log surfaces can be rewritten in user space, so missing suspicious tcontext values is not always proof.",
            "Readable AVC denial lines should be treated as audit-surface leakage, not as direct proof of a root process.",
            "comm, exe, path, and name fields inside AVC logs are supporting hints, not standalone proof of a live su daemon.",
        )
    }

    private fun policyWeaknessLabel(weakness: SelinuxPolicyWeakness?): String {
        return when (weakness) {
            SelinuxPolicyWeakness.NONE -> "Strong"
            SelinuxPolicyWeakness.MINOR -> "Minor drift"
            SelinuxPolicyWeakness.MODERATE -> "Review"
            SelinuxPolicyWeakness.SEVERE -> "Weak"
            null -> "Skipped"
        }
    }

    private fun policyWeaknessStatus(weakness: SelinuxPolicyWeakness?): DetectorStatus {
        return when (weakness) {
            SelinuxPolicyWeakness.NONE -> DetectorStatus.allClear()
            SelinuxPolicyWeakness.MINOR -> DetectorStatus.info(InfoKind.SUPPORT)
            SelinuxPolicyWeakness.MODERATE -> DetectorStatus.warning()
            SelinuxPolicyWeakness.SEVERE -> DetectorStatus.danger()
            null -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: SelinuxCheckResult): DetectorStatus {
        return when {
            result.permissionDenied -> DetectorStatus.allClear()
            result.isSecure == true -> DetectorStatus.allClear()
            result.isSecure == false -> DetectorStatus.danger()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun policyClassValue(policy: SelinuxPolicyAnalysis?): String {
        return when {
            policy == null -> "—"
            policy.classCount == 0 && policy.foundClasses.isEmpty() -> "Unreadable"
            else -> policy.classCount.toString()
        }
    }

    private fun policyClassStatus(policy: SelinuxPolicyAnalysis?): DetectorStatus {
        return when {
            policy == null -> DetectorStatus.info(InfoKind.SUPPORT)
            policy.classCount == 0 && policy.foundClasses.isEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
            policy.classCountOk -> DetectorStatus.allClear()
            else -> DetectorStatus.warning()
        }
    }

    private fun auditIntegrityLabel(analysis: SelinuxAuditIntegrityAnalysis?): String {
        return when (analysis?.state) {
            SelinuxAuditIntegrityState.CLEAR -> "No signal"
            SelinuxAuditIntegrityState.RESIDUE -> "Residue"
            SelinuxAuditIntegrityState.EXPOSED -> "Exposed"
            SelinuxAuditIntegrityState.TAMPERED -> "Tampered"
            SelinuxAuditIntegrityState.INCONCLUSIVE -> "Inconclusive"
            null -> "Skipped"
        }
    }

    private fun auditIntegrityStatus(analysis: SelinuxAuditIntegrityAnalysis?): DetectorStatus {
        return when (analysis?.state) {
            SelinuxAuditIntegrityState.CLEAR -> DetectorStatus.allClear()
            SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()
            SelinuxAuditIntegrityState.EXPOSED -> DetectorStatus.warning()
            SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
            SelinuxAuditIntegrityState.INCONCLUSIVE -> DetectorStatus.info(InfoKind.SUPPORT)
            null -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun modeStatus(mode: SelinuxMode): DetectorStatus {
        return when (mode) {
            SelinuxMode.ENFORCING -> DetectorStatus.allClear()
            SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
            SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
        }
    }

    private fun SelinuxReport.toDetectorStatus(): DetectorStatus {
        return when (stage) {
            SelinuxStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
            SelinuxStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
            SelinuxStage.READY -> when (mode) {
                SelinuxMode.ENFORCING -> when {
                    auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
                    policyAnalysis?.weakness == SelinuxPolicyWeakness.SEVERE ||
                            policyAnalysis?.weakness == SelinuxPolicyWeakness.MODERATE ||
                            auditIntegrity?.state == SelinuxAuditIntegrityState.EXPOSED ||
                            auditIntegrity?.state == SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()

                    else -> DetectorStatus.allClear()
                }

                SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
                SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
            }
        }
    }
}
