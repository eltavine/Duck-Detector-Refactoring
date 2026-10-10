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

import com.eltavine.duckdetector.capability.selinuxpolicy.data.DedicatedCarrierState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxPolicyloadSeqnoState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxProcAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityProbeResult
import com.eltavine.duckdetector.features.selinux.data.probes.SelinuxContextValidityState
import com.eltavine.duckdetector.features.selinux.domain.AppZygoteCarrierSupportState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupProfile
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyloadSeqnoLabels
import com.eltavine.duckdetector.features.selinux.domain.SelinuxProcAttrCurrentVerdict
import java.io.File

internal fun buildContextValidityMethod(
    result: SelinuxContextValidityProbeResult,
): SelinuxCheckResult {
    val verdict = when (result.state) {
        SelinuxContextValidityState.UNAVAILABLE -> SelinuxContextValidityVerdict.UNSUPPORTED
        SelinuxContextValidityState.CLEAN -> SelinuxContextValidityVerdict.CLEAN
        SelinuxContextValidityState.KSU_PRESENT -> SelinuxContextValidityVerdict.KSU_PRESENT
        SelinuxContextValidityState.AMBIGUOUS -> SelinuxContextValidityVerdict.AMBIGUOUS
        SelinuxContextValidityState.INCONSISTENT -> SelinuxContextValidityVerdict.SELF_TEST_FAILED
    }
    val carrier = when (result.carrierState) {
        DedicatedCarrierState.OK -> AppZygoteCarrierSupportState.AVAILABLE
        DedicatedCarrierState.FAILED -> AppZygoteCarrierSupportState.FAILED
        DedicatedCarrierState.UNTRUSTED -> AppZygoteCarrierSupportState.UNTRUSTED
    }

    val detail = buildList {
        add("Carrier=${result.carrierContext ?: "<unreadable>"}\n")
        add("Carrier state=${result.carrierState.label}\n")
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
        add("Evidence source=${EvidenceSource.DEDICATED_CARRIER.label}\n")
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
                add(
                    when (result.carrierState) {
                        DedicatedCarrierState.FAILED ->
                            "The dedicated app_zygote carrier failed before the oracle could produce a trusted result.\n"
                        DedicatedCarrierState.UNTRUSTED ->
                            "The dedicated app_zygote carrier was reachable but did not land in the expected app_zygote context.\n"
                        DedicatedCarrierState.OK ->
                            "The app_zygote carrier snapshot stayed unavailable.\n"
                    },
                )

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
        method = SelinuxOracle.CONTEXT_VALIDITY.label,
        status = verdict.label,
        isSecure = when (result.state) {
            SelinuxContextValidityState.UNAVAILABLE -> null
            SelinuxContextValidityState.CLEAN -> true
            SelinuxContextValidityState.KSU_PRESENT -> false
            SelinuxContextValidityState.AMBIGUOUS -> null
            SelinuxContextValidityState.INCONSISTENT -> null
        },
        permissionDenied = false,
        details = detail,
        oracle = SelinuxOracle.CONTEXT_VALIDITY,
        contextValidity = SelinuxContextValidityReading(
            verdict = verdict,
            carrier = carrier,
            repeatabilityFailed = result.state == SelinuxContextValidityState.INCONSISTENT,
        ),
    )
}

internal fun buildPolicyloadSeqnoMethod(
    result: SelinuxContextValidityProbeResult,
): SelinuxCheckResult {
    val state = runCatching {
        SelinuxPolicyloadSeqnoState.valueOf(result.policyloadSeqnoState.orEmpty())
    }.getOrDefault(SelinuxPolicyloadSeqnoState.UNAVAILABLE)
    val status = when (state) {
        SelinuxPolicyloadSeqnoState.CLEAN -> SelinuxPolicyloadSeqnoLabels.STATUS_CLEAN
        SelinuxPolicyloadSeqnoState.SUSPICIOUS -> SelinuxPolicyloadSeqnoLabels.STATUS_SUSPICIOUS
        SelinuxPolicyloadSeqnoState.STATUS_PAGE_FAULTED -> SelinuxPolicyloadSeqnoLabels.STATUS_PAGE_FAULTED
        SelinuxPolicyloadSeqnoState.INCONCLUSIVE -> SelinuxPolicyloadSeqnoLabels.STATUS_INCONCLUSIVE
        SelinuxPolicyloadSeqnoState.UNAVAILABLE -> SelinuxPolicyloadSeqnoLabels.STATUS_UNAVAILABLE
    }
    val detail = buildList {
        add("Evidence source=${EvidenceSource.DEDICATED_CARRIER.label}")
        add("Carrier=${result.policyloadSeqnoCarrierContext ?: result.carrierContext ?: "<unreadable>"}")
        add("zygotePreloadName required=yes")
        add("Probe attempted=${if (result.policyloadSeqnoProbeAttempted) "yes" else "no"}")
        result.policyloadSeqnoStatusSequence?.let { add("status.sequence=$it") }
        result.policyloadSeqnoStatusPolicyload?.let { add("status.policyload=$it") }
        result.policyloadSeqnoAccessSeqno?.let { add("access.avd.seqno=$it") }
        result.policyloadSeqnoProcessClass?.let { add("process class=$it") }
        // A faulted status page is the finding itself, so an unrelated carrier failure is not shown as its cause.
        (result.policyloadSeqnoFailureReason
            ?: result.failureReason.takeUnless { state == SelinuxPolicyloadSeqnoState.STATUS_PAGE_FAULTED })
            ?.let { add("Failure=$it") }
        result.policyloadSeqnoNotes.forEach(::add)
    }.joinToString(" | ")

    return SelinuxCheckResult(
        method = SelinuxOracle.POLICYLOAD_SEQNO.label,
        status = status,
        isSecure = when (state) {
            SelinuxPolicyloadSeqnoState.CLEAN -> true
            SelinuxPolicyloadSeqnoState.SUSPICIOUS,
            SelinuxPolicyloadSeqnoState.STATUS_PAGE_FAULTED -> false
            SelinuxPolicyloadSeqnoState.INCONCLUSIVE,
            SelinuxPolicyloadSeqnoState.UNAVAILABLE -> null
        },
        permissionDenied = false,
        details = detail,
        oracle = SelinuxOracle.POLICYLOAD_SEQNO,
    )
}

internal fun buildProcAttrCurrentMethod(
    result: SelinuxContextValidityProbeResult,
    source: EvidenceSource,
): SelinuxCheckResult {
    val outcomes = result.procAttrCurrentResults
    if (!result.procAttrCurrentProbeAttempted || outcomes.isEmpty()) {
        val reason = if (!result.procAttrCurrentProbeAttempted) "skipped" else "returned no results"
        return SelinuxCheckResult(
            method = SelinuxOracle.PROC_ATTR_CURRENT_WRITE.label,
            oracle = SelinuxOracle.PROC_ATTR_CURRENT_WRITE,
            status = SelinuxProcAttrCurrentVerdict.UNSUPPORTED.label,
            isSecure = null,
            permissionDenied = false,
            details = listOfNotNull(
                "Evidence source=${source.label}",
                result.procAttrCurrentFailureReason ?: "Dedicated app_zygote attr/current write probe $reason.",
            ).joinToString(" | "),
            attrCurrentVerdict = SelinuxProcAttrCurrentVerdict.UNSUPPORTED,
        )
    }

    val controls = outcomes.filter { it.label == SelinuxProcAttrCurrentResult.CONTROL_LABEL }
    val targets = outcomes.filter { it.label != SelinuxProcAttrCurrentResult.CONTROL_LABEL }
    val controlState = controls.singleOrNull()?.outcomeClass
    val controlled = controlState == SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED &&
        targets.size == SelinuxProcAttrCurrentResult.TARGET_COUNT &&
        targets.distinctBy { it.label }.size == targets.size
    val detected = if (controlled) targets.filter(SelinuxProcAttrCurrentResult::detected) else emptyList()
    val verdict = when {
        detected.isNotEmpty() -> SelinuxProcAttrCurrentVerdict.CONTEXT_RECOGNIZED
        controlled && targets.all { it.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL } ->
            SelinuxProcAttrCurrentVerdict.NOT_RECOGNIZED
        controlState == SelinuxProcAttrCurrentResult.OUTCOME_PERMISSION_LIMITED -> SelinuxProcAttrCurrentVerdict.PERMISSION_LIMITED
        controlState == SelinuxProcAttrCurrentResult.OUTCOME_UNSUPPORTED -> SelinuxProcAttrCurrentVerdict.UNSUPPORTED
        controlState == SelinuxProcAttrCurrentResult.OUTCOME_UNAVAILABLE -> SelinuxProcAttrCurrentVerdict.UNAVAILABLE
        else -> SelinuxProcAttrCurrentVerdict.INCONCLUSIVE
    }
    val status = if (detected.isEmpty()) verdict.label else "${verdict.label}: ${detected.joinToString { it.label }}"
    val detail = listOf(
        "Evidence source=${source.label}",
        "Repeated writes with stock/malformed controls; context recognition is supporting policy evidence, not root-family identification. " +
            "EINVAL cannot exclude a hidden policy; SID-table and timing observations share SELinux mechanisms.",
        outcomes.joinToString(" | ") { outcome ->
            "${outcome.label}=${outcome.outcomeClass} target=${outcome.targetContext} raw=${outcome.rawMessage}"
        },
    ).joinToString(" | ")

    return SelinuxCheckResult(
        method = SelinuxOracle.PROC_ATTR_CURRENT_WRITE.label,
        oracle = SelinuxOracle.PROC_ATTR_CURRENT_WRITE,
        status = status,
        isSecure = if (verdict == SelinuxProcAttrCurrentVerdict.CONTEXT_RECOGNIZED) false else null,
        permissionDenied = verdict == SelinuxProcAttrCurrentVerdict.PERMISSION_LIMITED,
        details = detail,
        attrCurrentDetections = detected.map { it.label },
        attrCurrentVerdict = verdict,
    )
}

internal enum class EvidenceSource(
    val label: String,
) {
    DEDICATED_CARRIER("dedicated app_zygote carrier"),
}

/** A per-CPU global counter profile, not a direct count of avc_has_perm() calls. */
internal fun buildAppZygoteAvcLookupMethod(snapshot: SelinuxAvcLookupSnapshot): SelinuxCheckResult {
    val state = snapshot.state
    val profile = if (state == SelinuxAvcLookupState.COLLECTED) snapshot.profile else 0
    val profileReading = if (state == SelinuxAvcLookupState.COLLECTED) when (profile) {
        1 -> SelinuxAvcLookupProfile.CONDITIONAL_DUPLICATE
        2 -> SelinuxAvcLookupProfile.BOTH_DUPLICATE
        3 -> SelinuxAvcLookupProfile.NATIVE_LIKE
        else -> SelinuxAvcLookupProfile.NOISY
    } else null
    val status = when {
        profile == 1 -> "A≈1 / B≈2 lookups per write (experimental)"
        profile == 2 -> "A≈2 / B≈2 lookups per write (experimental)"
        profile == 3 -> "A≈1 / B≈1 lookups per write (native-like)"
        state == SelinuxAvcLookupState.COLLECTED -> "Count rates inconsistent or noisy"
        state == SelinuxAvcLookupState.TIMING_ONLY -> "Timing only (AVC counters unavailable)"
        state == SelinuxAvcLookupState.PERMISSION_LIMITED -> "Permission limited"
        state == SelinuxAvcLookupState.UNSUPPORTED -> "Unsupported"
        state == SelinuxAvcLookupState.UNAVAILABLE || state == SelinuxAvcLookupState.NOT_COLLECTED -> "Unavailable"
        else -> "Inconclusive"
    }
    val details = buildString {
        append("app_zygote disposable child; two invalid contexts (A=invalid type, B=leading newline), both must return EINVAL; ")
        append("128 AB/BA pairs, 32 warmups; per-CPU global /sys/fs/selinux/avc/cache_stats.\n")
        append("State=$state; errno=${snapshot.error}; stats errno=${snapshot.statsError}; child end=${snapshot.childEnd}; ")
        append("CPU=${snapshot.cpu}/${snapshot.cpuRows}; rounds=${snapshot.rounds}; writes/batch=${snapshot.writesPerBatch}; ")
        append("A lookups=${snapshot.lookupsA}, B lookups=${snapshot.lookupsB}; ")
        append("rounds A=${snapshot.batchesA.joinToString()}, B=${snapshot.batchesB.joinToString()}; ")
        append("rate A=${snapshot.rateA?.let { "%.3f".format(java.util.Locale.ROOT, it) } ?: "n/a"}, ")
        append("rate B=${snapshot.rateB?.let { "%.3f".format(java.util.Locale.ROOT, it) } ?: "n/a"}; ")
        append("A median=${snapshot.medianANs} ns, B median=${snapshot.medianBNs} ns; ")
        append("paired A−B median=${snapshot.pairedDeltaNs} ns. ")
        append("Each rate includes other threads' AVC activity on the sampled CPU. ")
        append("The timing difference also includes context-parser and original-handler costs. ")
        append("A:1/B:2 or A:2/B:2 may fit a duplicate-check path but does not prove two calls, ")
        append("identify KernelSU, or establish the loaded commit; verify with Hide OFF/ON/OFF and call tracing. ")
        append("A:1/B:1 or inaccessible stats do not rule out hidden policy.")
    }
    return SelinuxCheckResult(
        method = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS.label,
        oracle = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS,
        status = status,
        // Unpaired single-state profiles are evidence for follow-up, NOT a
        // root verdict. Stock + same-kernel Hide OFF controls are not captured.
        isSecure = null,
        permissionDenied = state == SelinuxAvcLookupState.PERMISSION_LIMITED,
        details = details,
        avcLookupProfile = profileReading,
    )
}
