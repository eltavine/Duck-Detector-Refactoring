package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValiditySnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyRawState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxDirtySepolicyCompatibilityVerdict
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxRawContextCollectionState
import com.eltavine.duckdetector.capability.selinuxpolicy.data.sameEpochDecisionSplits
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult

/** Raw response integrity supplements, but does not replace, the existing Native/Java rule tracks. */
internal fun buildDirtyPolicyAccessProtocolMethod(snapshot: SelinuxContextValiditySnapshot): SelinuxCheckResult =
    SelinuxCheckResult(
        method = com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle.DIRTY_SEPOLICY_RAW.label,
        status = with(snapshot.dirtySepolicyRaw) {
            when {
                compatibility.verdict == SelinuxDirtySepolicyCompatibilityVerdict.ERROR -> "DirtySepolicy ERROR"
                state == SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT -> "Invalid access result"
                compatibility.verdict == SelinuxDirtySepolicyCompatibilityVerdict.WARNING -> "DirtySepolicy WARNING"
                statusWarnings.isNotEmpty() -> "Status header anomaly"
                recognizedContexts.isNotEmpty() -> "Root contexts observed"
                warningRules.isNotEmpty() -> "Allowed rules observed"
                controlsPassed && apiDisagreements.isNotEmpty() -> "Raw/API disagreement"
                sameEpochDecisionSplits().isNotEmpty() -> "Repeated access disagreement"
                state == SelinuxDirtySepolicyRawState.PARTIAL -> "Partially collected"
                state == SelinuxDirtySepolicyRawState.UNTRUSTED -> "Untrusted access controls"
                state == SelinuxDirtySepolicyRawState.UNAVAILABLE -> "Unavailable"
                state == SelinuxDirtySepolicyRawState.NOT_COLLECTED -> "Not collected"
                contextCollection == SelinuxRawContextCollectionState.PARTIAL -> "Context partially collected"
                allowedRules.isNotEmpty() -> "Policy observations"
                epochDeviation -> "Non-initial policy epoch"
                else -> "Response valid"
            }
        },
        isSecure = with(snapshot.dirtySepolicyRaw) {
            if (state == SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT ||
                compatibility.verdict == SelinuxDirtySepolicyCompatibilityVerdict.ERROR ||
                compatibility.verdict == SelinuxDirtySepolicyCompatibilityVerdict.WARNING ||
                (controlsPassed && warningRules.isNotEmpty()) ||
                recognizedContexts.isNotEmpty() || statusWarnings.isNotEmpty() ||
                (controlsPassed && apiDisagreements.isNotEmpty()) ||
                sameEpochDecisionSplits().isNotEmpty()) false else null
        },
        dirtySepolicyDanger = with(snapshot.dirtySepolicyRaw) {
            compatibility.verdict == SelinuxDirtySepolicyCompatibilityVerdict.WARNING ||
                compatibility.verdict == SelinuxDirtySepolicyCompatibilityVerdict.ERROR ||
                state == SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT ||
                (controlsPassed && apiDisagreements.isNotEmpty()) ||
                sameEpochDecisionSplits().isNotEmpty()
        },
        permissionDenied = false,
        details = buildList {
            val raw = snapshot.dirtySepolicyRaw
            add("Method=direct /sys/fs/selinux/access; replay of existing Dirty Policy rule queries")
            add("Transactions=${raw.observations.size}, distinct queries=${raw.observations.map { it.query }.distinct().size}")
            add("Six-field responses=${raw.observations.count { it.response != null && it.outcome != "INVALID_ACCESS_RESULT" }}")
            add("Invalid=${raw.observations.count { it.outcome == "INVALID_ACCESS_RESULT" }}")
            add("Unavailable=${raw.observations.count { it.outcome == "UNAVAILABLE" }}")
            add("Controls=${if (raw.controlsPassed) "passed" else "failed"}; stable=${raw.stable}")
            add("Access collection=${raw.state}; context collection=${raw.contextCollection}")
            add("DirtySepolicy 2.2 compatibility=${raw.compatibility.verdict}")
            if (raw.compatibility.reasons.isNotEmpty()) {
                add("DirtySepolicy original checks=${raw.compatibility.reasons.joinToString()}")
            }
            if (raw.allowedRules.isNotEmpty()) add("Trusted raw allows=${raw.allowedRules.joinToString()}")
            if (raw.warningRules.isNotEmpty()) add("Alert-eligible allowed rules=${raw.warningRules.joinToString()}")
            if (raw.apiDisagreements.isNotEmpty()) add("Raw vs Java disagreement=${raw.apiDisagreements.joinToString()}")
            if (raw.sameEpochDecisionSplits().isNotEmpty()) {
                add("Same-epoch repeated access disagreement=${raw.sameEpochDecisionSplits().joinToString()}")
            }
            add("Context controls=${if (raw.contextControlsPassed) "passed" else "not passed"}")
            add("Class=0 controls=${if (raw.classZeroControlsPassed) "passed" else "not passed"}")
            if (raw.recognizedContexts.isNotEmpty()) add("Context hits=${raw.recognizedContexts.joinToString()}")
            add("DirtySepolicy avdSeqNo=${raw.avdSeqno ?: "N/A"}; original query uses class=0")
            if (raw.epochDeviation) add("Non-initial avdSeqNo; may be a legitimate policy reload")
            if (raw.permissiveDecisionSeen) add("SELinux access permissive flags observed; API and raw decisions may differ normally")
            raw.statusEpoch?.let { add("Status baseline=$it") }
            if (raw.statusWarnings.isNotEmpty()) add("Status deviations=${raw.statusWarnings.joinToString()}")
            add("Context fallback=${raw.contextChecks.size} targets (context -> access -> controlled attr/current)")
            raw.contextChecks.forEach { context ->
                add("${context.context}: context=${context.contextNode}, access=${context.accessNode}, attr=${context.attrCurrent}, verdict=${context.verdict}")
            }
            raw.observations.groupBy { it.query }.forEach { (query, samples) ->
                add("$query: ${samples.joinToString("/") { it.outcome }}")
            }
            raw.failedQuery?.let { add("Failed query=$it") }
            raw.rawResponse?.let { add("Raw response=$it") }
            raw.failureReason?.let(::add)
            add("A valid response is transport evidence, not proof of a clean policy.")
        }.joinToString(" | "),
        oracle = com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle.DIRTY_SEPOLICY_RAW,
    )
