package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants

public enum class SelinuxDirtySepolicyRawState {
    NOT_COLLECTED,
    COMPLETE,
    PARTIAL,
    INVALID_ACCESS_RESULT,
    UNAVAILABLE,
    UNTRUSTED,
}

public data class SelinuxRawAccessObservation(
    val query: String,
    val outcome: String,
    val response: String? = null,
    val reason: String? = null,
    val stage: String? = null,
    val bytesRead: Int? = null,
    val errno: Int? = null,
)

public data class SelinuxRawContextObservation(
    val context: String,
    val contextNode: String,
    val accessNode: String,
    val attrCurrent: String,
    val verdict: String,
    val verifiedBy: SelinuxRawContextSource = SelinuxRawContextSource.NONE,
)

public enum class SelinuxRawContextSource {
    NONE,
    CONTEXT_NODE,
    ACCESS_CLASS_ZERO,
    ATTR_CURRENT,
}

public enum class SelinuxRawContextCollectionState {
    NOT_COLLECTED,
    COMPLETE,
    PARTIAL,
}

public data class SelinuxDirtySepolicyRawSnapshot(
    val state: SelinuxDirtySepolicyRawState = SelinuxDirtySepolicyRawState.NOT_COLLECTED,
    val failedQuery: String? = null,
    val rawResponse: String? = null,
    val failureReason: String? = null,
    val controlsPassed: Boolean = false,
    val stable: Boolean = false,
    val observations: List<SelinuxRawAccessObservation> = emptyList(),
    val contextChecks: List<SelinuxRawContextObservation> = emptyList(),
    val contextCollection: SelinuxRawContextCollectionState = SelinuxRawContextCollectionState.NOT_COLLECTED,
    val avdSeqno: Long? = null,
    val allowedRules: List<String> = emptyList(),
    val apiDisagreements: List<String> = emptyList(),
    val contextControlsPassed: Boolean = false,
    val recognizedContexts: List<String> = emptyList(),
    val classZeroControlsPassed: Boolean = false,
    val warningRules: List<String> = emptyList(),
    val statusEpoch: String? = null,
    val statusWarnings: List<String> = emptyList(),
    val epochDeviation: Boolean = false,
    val permissiveDecisionSeen: Boolean = false,
    val compatibility: SelinuxDirtySepolicyCompatibilityResult = SelinuxDirtySepolicyCompatibilityResult(),
)

private val RAW_CONTEXT_TARGETS = listOf(
    "u:r:ksu:s0", "u:object_r:ksu_file:s0", "u:r:magisk:s0",
    "u:object_r:magisk_file:s0", "u:object_r:lsposed_file:s0", "u:r:droidspacesd:s0",
    "u:r:msd_app:s0", "u:r:msd_daemon:s0", "u:object_r:xposed_data:s0",
    "u:r:adbroot:s0", "u:object_r:xposed_file:s0",
)

/** Direct selinuxfs transaction shared with the existing policyload/seqno oracle. */
/** Replays the existing Dirty Policy query plan through raw selinuxfs, not a second rule list. */
public class SelinuxDirtySepolicyRawProbe {
    internal fun inspect(
        snapshot: SelinuxContextValiditySnapshot,
        isUserBuild: Boolean,
        query: (String, String, String, String) -> String = { source, target, clazz, _ ->
            SelinuxRawAccess.query(source, target, SelinuxRawAccess.classId(clazz))
        },
        permissionMask: (String, String) -> UInt = SelinuxRawAccess::permissionMask,
        queryClassZero: (String, String) -> String = { source, target ->
            SelinuxRawAccess.query(source, target, 0)
        },
        checkContextNode: (String) -> String = SelinuxRawAccess::contextNode,
        statusHeader: SelinuxStatusHeader? = null,
        kernelRelease: String? = runCatching { Os.uname().release }.getOrNull(),
    ): SelinuxDirtySepolicyRawSnapshot {
        if (!snapshot.carrierMatchesExpected || !snapshot.available) {
            val skipped = SelinuxDirtySepolicyRawSnapshot(
                state = SelinuxDirtySepolicyRawState.UNTRUSTED,
                failureReason = "Expected an available, verified app_zygote carrier.",
            )
            return skipped.copy(compatibility = SelinuxDirtySepolicyCompatibility.evaluate(
                snapshot, skipped, statusHeader, isUserBuild, kernelRelease))
        }
        val observations = mutableListOf<SelinuxRawAccessObservation>()
        val classMasks = mutableMapOf<Pair<String, String>, UInt>()
        val rawCheck: (String, String, String, String) -> Boolean? = { source, target, clazz, permission ->
            val label = "$source -> $target:$clazz $permission"
            val result = try {
                val mask = classMasks.getOrPut(clazz to permission) { permissionMask(clazz, permission) }
                val response = query(source, target, clazz, permission)
                val decision = SelinuxRawAccess.parse(response)
                if (decision == null) {
                    observations += SelinuxRawAccessObservation(label, "INVALID_ACCESS_RESULT", response,
                        stage = "read", bytesRead = response.toByteArray(Charsets.UTF_8).size)
                    null
                } else {
                    val allowed = (decision.allowed and mask) == mask
                    observations += SelinuxRawAccessObservation(
                        label, if (allowed) "ALLOWED" else "DENIED", response,
                        stage = "read", bytesRead = response.toByteArray(Charsets.UTF_8).size,
                    )
                    allowed
                }
            } catch (error: SelinuxRawAccess.TransactionFailure) {
                if (error.stage == "write" && error.errorCode == OsConstants.EINVAL) {
                    observations += SelinuxRawAccessObservation(label, "INVALID_CONTEXT_EINVAL", reason = error.message,
                        stage = error.stage, bytesRead = error.count, errno = error.errorCode)
                    false
                } else {
                    observations += SelinuxRawAccessObservation(label, "UNAVAILABLE", reason = error.message,
                        stage = error.stage, bytesRead = error.count, errno = error.errorCode)
                    null
                }
            } catch (error: ErrnoException) {
                // The injectable query interface also permits callers to supply raw errno failures.
                if (error.errno == OsConstants.EINVAL) {
                    observations += SelinuxRawAccessObservation(label, "INVALID_CONTEXT_EINVAL", reason = "errno=${error.errno}",
                        stage = "write", errno = error.errno)
                    false
                } else {
                    observations += SelinuxRawAccessObservation(label, "UNAVAILABLE", reason = "errno=${error.errno}",
                        errno = error.errno)
                    null
                }
            } catch (error: Exception) {
                observations += SelinuxRawAccessObservation(label, "UNAVAILABLE", reason = error.message)
                null
            }
            result
        }
        val compatibilityControls = listOf(
            arrayOf("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent"),
            arrayOf("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context"),
        ).map { (source, target, clazz, permission) ->
            rawCheck(source, target, clazz, permission) to rawCheck(source, target, clazz, permission)
        }
        val compatibilityControlsPassed = compatibilityControls.all { (first, second) -> first == true && second == true }
        val rawChecks = snapshot.applyJavaDirtyPolicyResults(isUserBuild, rawCheck)
        val contextControlsPassed = runCatching {
            val carrier = requireNotNull(snapshot.carrierContext)
            val invalid = "u:r:duckdetector_context_oracle_sentinel:s0"
            checkContextNode(carrier) == "VALID" && checkContextNode(carrier) == "VALID" &&
                checkContextNode(invalid) == "INVALID" && checkContextNode(invalid) == "INVALID"
        }.getOrDefault(false)
        val javaComparisons = snapshot.comparableDirtyPolicyRules()
        val comparable = rawChecks.comparableDirtyPolicyRules().map { (name, allowed) ->
            Triple(name, allowed, javaComparisons[name])
        }
        // The target catalogue must not depend on whether the independent native child returned any rows.
        val attrResults = snapshot.procAttrCurrentResults
            .filter { it.label != SelinuxProcAttrCurrentResult.CONTROL_LABEL && it.targetContext.isNotBlank() }
            .associateBy { it.targetContext }
        val attrControlsPassed = snapshot.procAttrCurrentResults.size == SelinuxProcAttrCurrentResult.TARGET_COUNT + 1 &&
            attrResults.size == SelinuxProcAttrCurrentResult.TARGET_COUNT &&
            RAW_CONTEXT_TARGETS.all { it in attrResults } &&
            snapshot.procAttrCurrentResults.any {
            it.label == SelinuxProcAttrCurrentResult.CONTROL_LABEL &&
                it.outcomeClass == SelinuxProcAttrCurrentResult.OUTCOME_CONTROLS_PASSED
            }
        fun classZero(source: String, target: String): String {
            val label = "$source -> $target:class=0"
            return try {
                val response = queryClassZero(source, target)
                val decision = SelinuxRawAccess.parse(response)
                observations += SelinuxRawAccessObservation(label,
                    if (decision == null) "INVALID_ACCESS_RESULT" else "VALID_ACCESS", response,
                    stage = "read", bytesRead = response.toByteArray(Charsets.UTF_8).size)
                if (decision == null) "INVALID_ACCESS_RESULT" else "VALID"
            } catch (error: SelinuxRawAccess.TransactionFailure) {
                val outcome = if (error.stage == "write" && error.errorCode == OsConstants.EINVAL) "INVALID" else "UNAVAILABLE"
                observations += SelinuxRawAccessObservation(label,
                    if (outcome == "INVALID") "INVALID_CONTEXT_EINVAL" else "UNAVAILABLE",
                    reason = error.message, stage = error.stage, bytesRead = error.count, errno = error.errorCode)
                outcome
            } catch (error: ErrnoException) {
                val invalid = error.errno == OsConstants.EINVAL
                observations += SelinuxRawAccessObservation(
                    label,
                    if (invalid) "INVALID_CONTEXT_EINVAL" else "UNAVAILABLE",
                    reason = "errno=${error.errno}",
                    stage = "write",
                    errno = error.errno,
                )
                if (invalid) "INVALID" else "UNAVAILABLE"
            } catch (error: Exception) {
                observations += SelinuxRawAccessObservation(label, "UNAVAILABLE", reason = error.message)
                "UNAVAILABLE"
            }
        }
        val positiveClassZero = snapshot.carrierContext?.let { carrier ->
            listOf(classZero(carrier, carrier), classZero(carrier, carrier))
        }.orEmpty()
        val invalidContext = "u:r:duckdetector_context_oracle_sentinel:s0"
        val negativeClassZero = listOf(classZero(invalidContext, invalidContext),
            classZero(invalidContext, invalidContext))
        val classZeroControlsPassed = positiveClassZero.size == 2 && positiveClassZero.all { it == "VALID" } &&
            negativeClassZero.all { it == "INVALID" }
        val contextChecks = RAW_CONTEXT_TARGETS.map { context ->
            val target = attrResults[context]
            val contextState = runCatching { checkContextNode(context) }
                .getOrElse { "UNAVAILABLE:${it.message}" }
            var accessState = "SKIPPED"
            var attrState = "SKIPPED"
            var verifiedBy = SelinuxRawContextSource.NONE
            val verdict = if (contextState == "VALID" && contextControlsPassed) {
                verifiedBy = SelinuxRawContextSource.CONTEXT_NODE
                "VALID"
            } else {
                // A failed first-layer control must not veto an independently verified fallback.
                accessState = classZero(context, context)
                if (accessState == "VALID" && classZeroControlsPassed) {
                    verifiedBy = SelinuxRawContextSource.ACCESS_CLASS_ZERO
                    "VALID"
                } else {
                    attrState = if (!attrControlsPassed) "UNTRUSTED" else target?.outcomeClass ?: "UNAVAILABLE"
                    when (attrState) {
                        SelinuxProcAttrCurrentResult.OUTCOME_CONTEXT_RECOGNIZED -> {
                            verifiedBy = SelinuxRawContextSource.ATTR_CURRENT
                            "VALID"
                        }
                        SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL -> "INVALID"
                        "UNAVAILABLE" -> "UNAVAILABLE"
                        else -> "INCONCLUSIVE"
                    }
                }
            }
            SelinuxRawContextObservation(context, contextState, accessState, attrState, verdict, verifiedBy)
        }
        val contextCollection = if (contextChecks.all { it.verdict == "VALID" || it.verdict == "INVALID" }) {
            SelinuxRawContextCollectionState.COMPLETE
        } else SelinuxRawContextCollectionState.PARTIAL
        val avdSeqno = try {
            val source = "u:r:untrusted_app:s0"
            val response = queryClassZero(source, source)
            val decision = SelinuxRawAccess.parse(response)
            observations += SelinuxRawAccessObservation(
                "$source -> $source:class=0",
                if (decision == null) "INVALID_ACCESS_RESULT" else "VALID_ACCESS",
                response,
                stage = "read", bytesRead = response.toByteArray(Charsets.UTF_8).size,
            )
            decision?.seqno
        } catch (error: ErrnoException) {
            observations += SelinuxRawAccessObservation(
                "untrusted_app -> untrusted_app:class=0", "UNAVAILABLE", reason = "errno=${error.errno}",
            )
            null
        } catch (error: Exception) {
            observations += SelinuxRawAccessObservation(
                "untrusted_app -> untrusted_app:class=0", "UNAVAILABLE", reason = error.message,
            )
            null
        }
        val statusEpoch = when {
            statusHeader == null -> "Status page unavailable; epoch baseline not evaluated"
            statusHeader.version != 1L -> "Unknown status version=${statusHeader.version}"
            statusHeader.sequence % 2L != 0L -> "Status sequence in transition=${statusHeader.sequence}"
            statusHeader.sequence == 0L && statusHeader.policyload == 0L -> "Legacy initial status counters"
            statusHeader.sequence == 4L && statusHeader.policyload == 1L -> "Modern initial status counters"
            else -> "Non-initial status counters: sequence=${statusHeader.sequence}, policyload=${statusHeader.policyload}"
        }
        val statusWarnings = buildList {
            if (statusHeader?.version == 1L) {
                if (statusHeader.enforcing != 1L) add("Status header enforcing=${statusHeader.enforcing}")
                if (statusHeader.denyUnknown != 1L) add("Status header deny_unknown=${statusHeader.denyUnknown}")
            }
        }
        val allDecisions = observations.mapNotNull { sample ->
            sample.response?.let(SelinuxRawAccess::parse)
        }
        val permissiveDecisionSeen = allDecisions.any { (it.flags and 1u) != 0u }
        val samePolicyEpoch = allDecisions.map { it.seqno }.distinct().size == 1
        val malformed = observations.firstOrNull { it.outcome == "INVALID_ACCESS_RESULT" }
        val unavailable = observations.firstOrNull { it.outcome == "UNAVAILABLE" }
        // Raw collection covers the new 2.2 edges. Their instability invalidates Raw
        // completeness, but must not revoke the original Java/Native oracle's trust.
        val repeatedRawStable = observations.groupBy { it.query }.values.none { samples ->
            samples.size == 2 && samples[0].outcome != samples[1].outcome
        }
        val controlsPassed = compatibilityControlsPassed && rawChecks.javaDirtyPolicyControlsPassed
        val state = when {
            malformed != null -> SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT
            !controlsPassed ->
                SelinuxDirtySepolicyRawState.UNTRUSTED
            observations.isEmpty() -> SelinuxDirtySepolicyRawState.UNAVAILABLE
            unavailable != null || !rawChecks.javaDirtyPolicyStable || !repeatedRawStable ->
                SelinuxDirtySepolicyRawState.PARTIAL
            else -> SelinuxDirtySepolicyRawState.COMPLETE
        }
        val trustedAllows = if (controlsPassed) comparable.filter { it.second == true }.map { it.first } else emptyList()
        val result = SelinuxDirtySepolicyRawSnapshot(
            state = state,
            failedQuery = malformed?.query ?: unavailable?.query,
            rawResponse = malformed?.response,
            failureReason = when (state) {
                SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT -> "Invalid access result: ${malformed?.response}"
                SelinuxDirtySepolicyRawState.UNAVAILABLE -> unavailable?.reason ?: rawChecks.javaDirtyPolicyFailureReason
                SelinuxDirtySepolicyRawState.PARTIAL -> unavailable?.reason ?: rawChecks.javaDirtyPolicyFailureReason
                SelinuxDirtySepolicyRawState.UNTRUSTED -> rawChecks.javaDirtyPolicyFailureReason
                    ?: "DirtySepolicy access self-check failed."
                else -> null
            },
            controlsPassed = controlsPassed,
            stable = rawChecks.javaDirtyPolicyStable && repeatedRawStable &&
                compatibilityControls.all { (first, second) -> first != null && first == second },
            observations = observations,
            contextChecks = contextChecks,
            contextCollection = contextCollection,
            avdSeqno = avdSeqno,
            allowedRules = trustedAllows,
            apiDisagreements = if (controlsPassed && snapshot.javaDirtyPolicyTrusted &&
                !permissiveDecisionSeen && samePolicyEpoch) {
                comparable.filter { it.second != null && it.third != null && it.second != it.third }
                    .map { it.first }
            } else emptyList(),
            warningRules = trustedAllows.filter(SelinuxDirtyPolicyRuleClassification::isAlertEligible),
            statusEpoch = statusEpoch + when {
                avdSeqno == null -> "; avdSeqNo unavailable"
                avdSeqno != 1L -> "; avdSeqNo=$avdSeqno (non-initial epoch; reload or policy difference)"
                else -> "; avdSeqNo=1"
            },
            statusWarnings = statusWarnings,
            epochDeviation = avdSeqno != null && avdSeqno != 1L,
            permissiveDecisionSeen = permissiveDecisionSeen,
            contextControlsPassed = contextControlsPassed,
            classZeroControlsPassed = classZeroControlsPassed,
            recognizedContexts = contextChecks.filter {
                it.verdict == "VALID" && it.verifiedBy != SelinuxRawContextSource.NONE
            }.map { it.context },
        )
        return result.copy(compatibility = SelinuxDirtySepolicyCompatibility.evaluate(
            snapshot, result, statusHeader, isUserBuild, kernelRelease))
    }
}
