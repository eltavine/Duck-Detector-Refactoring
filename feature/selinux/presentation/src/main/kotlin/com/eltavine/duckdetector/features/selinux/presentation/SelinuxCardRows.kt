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
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyNoteKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyRuleSet
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxRuleVerdict
import com.eltavine.duckdetector.features.selinux.domain.contextValiditySupportState
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxDetailRowModel
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxImpactItemModel

internal fun buildStateRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
    val detectionPath = when {
        report.mode == SelinuxMode.UNKNOWN -> "Not resolved"
        report.paradoxDetected -> "Paradox logic"
        report.methods.any { it.readsEnforcing } -> "Direct confirmation"

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

internal fun buildMethodRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
    val msdRows = report.methods.filter { it.policyRule?.set == SelinuxPolicyRuleSet.MSD }
    val droidspacesRows = report.methods.filter { it.policyRule?.set == SelinuxPolicyRuleSet.DROIDSPACES }
    var msdInserted = false
    var droidspacesInserted = false
    return buildList {
        report.methods.forEach { result ->
            when (result.policyRule?.set) {
                SelinuxPolicyRuleSet.MSD -> if (!msdInserted) {
                    buildAggregatedMsdMethodRow(msdRows)?.let(::add)
                    msdInserted = true
                }

                SelinuxPolicyRuleSet.DROIDSPACES -> if (!droidspacesInserted) {
                    buildAggregatedDroidspacesMethodRow(droidspacesRows)?.let(::add)
                    droidspacesInserted = true
                }

                else -> add(methodRow(result))
            }
        }
    }
}

private fun methodRow(result: SelinuxCheckResult): SelinuxDetailRowModel {
    if (result.oracle == SelinuxOracle.SIDTAB_CONSISTENCY && result.sidtab != null) return sidtabRow(result)
    if (result.oracle == SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS && result.avcLookup != null) return avcLookupRow(result)
    return SelinuxDetailRowModel(
        label = result.method,
        value = result.status,
        status = methodStatus(result),
        detail = result.details,
    )
}

private fun buildAggregatedMsdMethodRow(results: List<SelinuxCheckResult>): SelinuxDetailRowModel? {
    if (results.isEmpty()) {
        return null
    }
    val allowed = results.ruleEdges(SelinuxRuleVerdict.ALLOWED)
    val denied = results.ruleEdges(SelinuxRuleVerdict.DENIED)
    val unavailable = results.ruleEdges(SelinuxRuleVerdict.UNAVAILABLE)
    val aggregateResult = SelinuxCheckResult(
        method = "Dirty sepolicy rule: MSD",
        status = when {
            allowed.isNotEmpty() -> SelinuxRuleVerdict.ALLOWED.label
            unavailable.isNotEmpty() -> SelinuxRuleVerdict.UNAVAILABLE.label
            else -> SelinuxRuleVerdict.DENIED.label
        },
        isSecure = when {
            allowed.isNotEmpty() -> false
            unavailable.isNotEmpty() -> null
            else -> true
        },
        permissionDenied = results.all { it.permissionDenied },
        details = null,
        dirtyPolicyTrusted = results.any { it.dirtyPolicyTrusted },
    )
    return SelinuxDetailRowModel(
        label = aggregateResult.method,
        value = buildList {
            if (allowed.isNotEmpty()) {
                add("${allowed.size} allowed")
            }
            if (denied.isNotEmpty()) {
                add("${denied.size} denied")
            }
            if (unavailable.isNotEmpty()) {
                add("${unavailable.size} unavailable")
            }
        }.joinToString(", "),
        status = methodStatus(aggregateResult),
        detail = buildList {
            if (allowed.isNotEmpty()) {
                add("Allowed: ${allowed.joinToString()}")
            }
            if (denied.isNotEmpty()) {
                add("Denied: ${denied.joinToString()}")
            }
            if (unavailable.isNotEmpty()) {
                add("Unavailable: ${unavailable.joinToString()}")
            }
        }.joinToString(" | "),
    )
}

private fun buildAggregatedDroidspacesMethodRow(results: List<SelinuxCheckResult>): SelinuxDetailRowModel? {
    if (results.isEmpty()) {
        return null
    }
    val allowed = results.ruleEdges(SelinuxRuleVerdict.ALLOWED)
    val denied = results.ruleEdges(SelinuxRuleVerdict.DENIED)
    val unavailable = results.ruleEdges(SelinuxRuleVerdict.UNAVAILABLE)
    val aggregateResult = SelinuxCheckResult(
        method = "Dirty sepolicy rule: Droidspaces",
        status = when {
            allowed.isNotEmpty() -> SelinuxRuleVerdict.ALLOWED.label
            unavailable.isNotEmpty() -> SelinuxRuleVerdict.UNAVAILABLE.label
            else -> SelinuxRuleVerdict.DENIED.label
        },
        isSecure = when {
            allowed.isNotEmpty() -> false
            unavailable.isNotEmpty() -> null
            else -> true
        },
        permissionDenied = results.all { it.permissionDenied },
        details = null,
        dirtyPolicyTrusted = results.any { it.dirtyPolicyTrusted },
    )
    return SelinuxDetailRowModel(
        label = aggregateResult.method,
        value = buildList {
            if (allowed.isNotEmpty()) {
                add("${allowed.size} allowed")
            }
            if (denied.isNotEmpty()) {
                add("${denied.size} denied")
            }
            if (unavailable.isNotEmpty()) {
                add("${unavailable.size} unavailable")
            }
        }.joinToString(", "),
        status = methodStatus(aggregateResult),
        detail = buildList {
            if (allowed.isNotEmpty()) {
                add("Allowed: ${allowed.joinToString()}")
            }
            if (denied.isNotEmpty()) {
                add("Denied: ${denied.joinToString()}")
            }
            if (unavailable.isNotEmpty()) {
                add("Unavailable: ${unavailable.joinToString()}")
            }
        }.joinToString(" | "),
    )
}

private fun List<SelinuxCheckResult>.ruleEdges(verdict: SelinuxRuleVerdict): List<String> =
    mapNotNull { it.policyRule }.filter { it.verdict == verdict }.map { it.edge }

private fun methodStatus(result: SelinuxCheckResult): DetectorStatus {
    if (result.oracle == SelinuxOracle.ATTR_CURRENT_TIMING) {
        return if (result.isSecure == false) DetectorStatus.warning()
        else DetectorStatus.info(InfoKind.SUPPORT)
    }
    if (result.oracle == SelinuxOracle.CONTEXT_VALIDITY) {
        return when (result.contextValidity?.verdict) {
            SelinuxContextValidityVerdict.KSU_PRESENT -> DetectorStatus.danger()
            SelinuxContextValidityVerdict.CLEAN -> DetectorStatus.allClear()
            SelinuxContextValidityVerdict.AMBIGUOUS -> DetectorStatus.warning()
            SelinuxContextValidityVerdict.SELF_TEST_FAILED -> DetectorStatus.warning()
            SelinuxContextValidityVerdict.UNSUPPORTED,
            null -> when (contextValiditySupportState(result)) {
                AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                AppZygoteCarrierSupportState.AVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)
            }
        }
    }
    if (result.oracle == SelinuxOracle.PROC_ATTR_CURRENT_WRITE) {
        return when {
            result.isSecure == false -> DetectorStatus.warning()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    if (result.oracle == SelinuxOracle.POLICYLOAD_SEQNO) {
        return when {
            result.isSecure == false -> DetectorStatus.danger()
            result.isSecure == true -> DetectorStatus.allClear()
            else -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }
    return when {
        result.permissionDenied -> DetectorStatus.allClear()
        result.isSecure == true -> DetectorStatus.allClear()
        result.isSecure == false -> DetectorStatus.danger()
        else -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun buildPolicyRows(policy: SelinuxPolicyAnalysis?): List<SelinuxDetailRowModel> {
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

internal fun buildPolicyNotes(policy: SelinuxPolicyAnalysis?): List<SelinuxImpactItemModel> {
    return policy?.notes?.map { note ->
        SelinuxImpactItemModel(text = note.text, status = note.kind.status())
    }.orEmpty()
}

private fun SelinuxPolicyNoteKind.status(): DetectorStatus = when (this) {
    SelinuxPolicyNoteKind.VERSION_MEETS_MINIMUM,
    SelinuxPolicyNoteKind.CONTEXT_TYPE_NORMAL -> DetectorStatus.allClear()

    SelinuxPolicyNoteKind.VERSION_BELOW_MINIMUM,
    SelinuxPolicyNoteKind.CLASSES_MISSING,
    SelinuxPolicyNoteKind.PERMISSIVE_DOMAINS_FOUND -> DetectorStatus.warning()

    // Keeps the status a keyword match gave these notes; see "SELinux note statuses" in the follow-ups.
    SelinuxPolicyNoteKind.NO_PERMISSIVE_DOMAINS -> DetectorStatus.warning()

    SelinuxPolicyNoteKind.DANGEROUS_CONTEXT_TYPES -> DetectorStatus.danger()

    SelinuxPolicyNoteKind.VERSION_UNREADABLE,
    SelinuxPolicyNoteKind.CLASSES_COMPLETE,
    SelinuxPolicyNoteKind.CLASSES_UNREADABLE -> DetectorStatus.info(InfoKind.SUPPORT)
}

internal fun policyWeaknessLabel(weakness: SelinuxPolicyWeakness?): String {
    return when (weakness) {
        SelinuxPolicyWeakness.NONE -> "Strong"
        SelinuxPolicyWeakness.MINOR -> "Minor drift"
        SelinuxPolicyWeakness.MODERATE -> "Review"
        SelinuxPolicyWeakness.SEVERE -> "Weak"
        null -> "Skipped"
    }
}

internal fun policyWeaknessStatus(weakness: SelinuxPolicyWeakness?): DetectorStatus {
    return when (weakness) {
        SelinuxPolicyWeakness.NONE -> DetectorStatus.allClear()
        SelinuxPolicyWeakness.MINOR -> DetectorStatus.info(InfoKind.SUPPORT)
        SelinuxPolicyWeakness.MODERATE -> DetectorStatus.warning()
        SelinuxPolicyWeakness.SEVERE -> DetectorStatus.danger()
        null -> DetectorStatus.info(InfoKind.SUPPORT)
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
