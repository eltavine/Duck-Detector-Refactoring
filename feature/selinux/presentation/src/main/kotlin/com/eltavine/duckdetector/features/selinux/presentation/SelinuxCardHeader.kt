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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.AppZygoteCarrierSupportState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabVerdict
import com.eltavine.duckdetector.features.selinux.domain.sidtabReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import com.eltavine.duckdetector.features.selinux.domain.contextValidityResult
import com.eltavine.duckdetector.features.selinux.domain.contextValiditySupportState
import com.eltavine.duckdetector.features.selinux.domain.firstTrustedPolicyRuleHit
import com.eltavine.duckdetector.features.selinux.domain.policyloadSeqnoResult
import com.eltavine.duckdetector.features.selinux.domain.procAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxHeaderFact
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxHeaderFactModel

internal fun buildSubtitle(report: SelinuxReport): String {
    return when (report.stage) {
        SelinuxStage.LOADING -> "sysfs + getenforce + proc attr + app_zygote zygotePreload seqno + context oracle + policy + audit"
        SelinuxStage.FAILED -> "local status probe failed"
        SelinuxStage.READY -> buildString {
            append("7 local checks")
            if (report.methods.any { it.oracle == SelinuxOracle.ATTR_CURRENT_TIMING }) {
                append(" + attr/current timing")
            }
            if (report.policyAnalysis != null) {
                append(" + policy")
            }
            if (report.auditIntegrity != null) {
                append(" + audit integrity + side-channel")
            }
        }
    }
}

internal fun buildVerdict(report: SelinuxReport): String {
    val contextValidity = contextValidityResult(report)
    val procAttrCurrent = procAttrCurrentResult(report)
    val policyloadSeqno = policyloadSeqnoResult(report)
    val dirtyPolicyHit = firstTrustedPolicyRuleHit(report)
    val repeatabilityFailed = contextValidity?.contextValidity?.repeatabilityFailed == true
    val appZygoteCarrierState = contextValiditySupportState(contextValidity)
    return when (report.stage) {
        SelinuxStage.LOADING -> "Scanning SELinux state"
        SelinuxStage.FAILED -> "SELinux scan failed"
        SelinuxStage.READY -> when (report.mode) {
            SelinuxMode.ENFORCING -> when {
                report.auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> "Enforcing with audit rewrite"
                contextValidity?.contextValidity?.verdict == SelinuxContextValidityVerdict.KSU_PRESENT ->
                    "Enforcing with KSU context materialized"
                policyloadSeqno?.isSecure == false -> "Enforcing with app_zygote seqno split"
                procAttrCurrent?.isSecure == false -> "Enforcing with app_zygote attr-write anomaly"
                report.methods.any { it.oracle == SelinuxOracle.ATTR_CURRENT_TIMING && it.isSecure == false } ->
                    "Enforcing with SELinux attr/current timing anomaly"
                dirtyPolicyHit != null -> trustedPolicyRuleVerdict()
                appZygoteCarrierState == AppZygoteCarrierSupportState.UNTRUSTED ->
                    "Enforcing with untrusted app_zygote carrier"
                sidtabReading(report)?.verdict == SelinuxSidtabVerdict.DISCREPANCY_OBSERVED ->
                    "Enforcing with SID-table query discrepancy"
                appZygoteCarrierState == AppZygoteCarrierSupportState.FAILED ->
                    "Enforcing with reduced app_zygote coverage"

                contextValidity?.contextValidity?.verdict == SelinuxContextValidityVerdict.SELF_TEST_FAILED ->
                    if (repeatabilityFailed) {
                        "Enforcing with unstable context oracle"
                    } else {
                        "Enforcing with untrusted context oracle"
                    }

                contextValidity?.contextValidity?.verdict == SelinuxContextValidityVerdict.AMBIGUOUS ->
                    "Enforcing with context split"

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

internal fun buildSummary(report: SelinuxReport): String {
    val contextValidity = contextValidityResult(report)
    val procAttrCurrent = procAttrCurrentResult(report)
    val policyloadSeqno = policyloadSeqnoResult(report)
    val dirtyPolicyHit = firstTrustedPolicyRuleHit(report)
    // Coverage states stay in the method row; only a finding belongs in the summary.
    val sidtabDiscrepancy = sidtabReading(report)?.takeIf { it.verdict == SelinuxSidtabVerdict.DISCREPANCY_OBSERVED }
    val repeatabilityFailed = contextValidity?.contextValidity?.repeatabilityFailed == true
    val appZygoteCarrierState = contextValiditySupportState(contextValidity)
    return when (report.stage) {
        SelinuxStage.LOADING ->
            "Checking sysfs, getenforce, /proc/self/attr/current, and app_zygote attr writes before deriving final mode with paradox logic."

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
                        if (sidtabDiscrepancy != null) {
                            "SELinux is enforcing, but the SID-table experiment did not match stock registration behavior."
                        } else {
                            "SELinux is enforcing and the visible policy surface looks internally consistent."
                        }
                }
                val extra = buildList {
                    if (report.paradoxDetected) {
                        add("Permission-denied probes also reinforced the enforcing verdict.")
                    }
                    if (procAttrCurrent?.isSecure == false) {
                        add(
                            "The dedicated app_zygote carrier hit anomalous /proc/self/attr/current write outcomes while probing privileged contexts: ${
                                procAttrCurrent.attrCurrentDetections.joinToString()
                            }.",
                        )
                    }
                    if (policyloadSeqno?.isSecure == false) {
                        add("The zygotePreload app_zygote carrier observed a policyload/access seqno split; treat this as KernelSU-specific evidence bounded to the preload carrier.")
                    }
                    if (report.methods.any { it.oracle == SelinuxOracle.ATTR_CURRENT_TIMING && it.isSecure == false }) {
                        add("Repeated ordinary-app attr/current writes revealed a content-dependent timing asymmetry. This is an experimental, device-dependent clue, not conclusive attribution to KernelSU.")
                    }
                    if (dirtyPolicyHit != null) {
                        add(trustedPolicyRuleSummary(dirtyPolicyHit))
                    }
                    sidtabDiscrepancy?.let { add(sidtabExplanation(it)) }
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
                val contextNote = when (contextValidity?.contextValidity?.verdict) {
                    SelinuxContextValidityVerdict.KSU_PRESENT ->
                        "The context validity oracle accepted both KSU-specific contexts from the current carrier."

                    SelinuxContextValidityVerdict.CLEAN ->
                        "The context validity oracle rejected both KSU-specific contexts in live policy."

                    SelinuxContextValidityVerdict.SELF_TEST_FAILED ->
                        if (repeatabilityFailed) {
                            "The context validity oracle repeated inconsistently, so its KSU verdict was not trusted."
                        } else {
                            "The context validity oracle failed its self-test, so its KSU verdict was not trusted."
                        }

                    SelinuxContextValidityVerdict.AMBIGUOUS ->
                        "The context validity oracle split across the two KSU-specific contexts."

                    SelinuxContextValidityVerdict.UNSUPPORTED ->
                        when (appZygoteCarrierState) {
                            AppZygoteCarrierSupportState.UNTRUSTED ->
                                buildString {
                                    append("The dedicated app_zygote carrier did not land in the expected app_zygote context, so app_zygote-only SELinux evidence was not trusted.")
                                    contextValidity.details?.let {
                                        append(' ')
                                        append(it)
                                    }
                                }
                            AppZygoteCarrierSupportState.FAILED ->
                                buildString {
                                    append("The dedicated app_zygote carrier failed before the oracle produced a trusted result, so app_zygote-only SELinux coverage was reduced.")
                                    contextValidity.details?.let {
                                        append(' ')
                                        append(it)
                                    }
                                }
                            AppZygoteCarrierSupportState.AVAILABLE ->
                                contextValidity.details ?: "The context validity oracle stayed unavailable."
                        }

                    else -> null
                }
                listOf(base)
                    .plus(extra)
                    .plus(contextNote?.let { listOf(it) }.orEmpty())
                    .joinToString(" ")
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

internal fun buildHeaderFacts(report: SelinuxReport): List<SelinuxHeaderFactModel> {
    val policy = report.policyAnalysis
    return listOf(
        SelinuxHeaderFactModel(
            fact = SelinuxHeaderFact.MODE,
            value = report.resolvedStatusLabel,
            status = modeStatus(report.mode),
        ),
        SelinuxHeaderFactModel(
            fact = SelinuxHeaderFact.POLICY,
            value = policyWeaknessLabel(policy?.weakness),
            status = policyWeaknessStatus(policy?.weakness),
        ),
        SelinuxHeaderFactModel(
            fact = SelinuxHeaderFact.AUDIT,
            value = auditIntegrityLabel(report.auditIntegrity),
            status = auditIntegrityStatus(report.auditIntegrity),
        ),
        SelinuxHeaderFactModel(
            fact = SelinuxHeaderFact.CONTEXT,
            value = report.contextType ?: "Unknown",
            status = when {
                policy?.dangerousTypesFound?.isNotEmpty() == true -> DetectorStatus.danger()
                report.contextType != null -> DetectorStatus.allClear()
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
        ),
    )
}

internal fun modeStatus(mode: SelinuxMode): DetectorStatus {
    return when (mode) {
        SelinuxMode.ENFORCING -> DetectorStatus.allClear()
        SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
        SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
    }
}
