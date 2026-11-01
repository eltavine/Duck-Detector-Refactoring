package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtySepolicyCompatibilityTest {
    private val carrier = SelinuxContextValiditySnapshot(
        available = true,
        carrierContext = "u:r:app_zygote:s0:c512,c768",
        carrierMatchesExpected = true,
        selinuxEnabled = true,
        selinuxEnforced = true,
        pidContextMatchesCurrent = true,
        procSelfContextMatchesCurrent = true,
    )
    private val oldStatus = SelinuxStatusHeader(1, 0, 1, 0, 1)
    private val newStatus = SelinuxStatusHeader(1, 4, 1, 1, 1)
    private val edges = listOf(
        "u:r:app_zygote:s0 -> u:r:app_zygote:s0:process setcurrent",
        "u:r:app_zygote:s0 -> u:r:kernel:s0:security check_context",
        "u:r:system_server:s0 -> u:r:system_server:s0:process execmem",
        "u:r:shell:s0 -> u:r:su:s0:process transition",
        "u:object_r:rootfs:s0 -> u:object_r:tmpfs:s0:filesystem associate",
        "u:r:kernel:s0 -> u:object_r:tmpfs:s0:fifo_file open",
        "u:r:kernel:s0 -> u:object_r:adb_data_file:s0:file read",
        "u:r:system_server:s0 -> u:object_r:apk_data_file:s0:file execute",
        "u:r:dex2oat:s0 -> u:object_r:dex2oat_exec:s0:file execute_no_trans",
        "u:r:zygote:s0 -> u:object_r:adb_data_file:s0:dir search",
    )
    private val contexts = listOf(
        "u:r:adbroot:s0", "u:r:magisk:s0", "u:object_r:magisk_file:s0",
        "u:r:ksu:s0", "u:object_r:ksu_file:s0", "u:object_r:lsposed_file:s0",
        "u:object_r:xposed_data:s0", "u:object_r:xposed_file:s0",
    )

    private fun raw(
        allowed: Set<String> = emptySet(),
        recognized: Set<String> = emptySet(),
        missingEdges: Set<String> = emptySet(),
        malformedEdges: Set<String> = emptySet(),
        avdSeqno: Long? = 1L,
    ): SelinuxDirtySepolicyRawSnapshot {
        val samples = edges.filterNot { it in missingEdges }.flatMap { key ->
            List(2) {
                SelinuxRawAccessObservation(key, when {
                    key in malformedEdges -> "INVALID_ACCESS_RESULT"
                    key in allowed || key.endsWith("setcurrent") || key.endsWith("check_context") -> "ALLOWED"
                    else -> "DENIED"
                })
            }
        }
        return SelinuxDirtySepolicyRawSnapshot(
            state = SelinuxDirtySepolicyRawState.COMPLETE,
            observations = samples,
            avdSeqno = avdSeqno,
            contextChecks = contexts.map { key ->
                SelinuxRawContextObservation(
                    context = key, contextNode = if (key in recognized) "VALID" else "INVALID",
                    accessNode = if (key in recognized) "SKIPPED" else "INVALID",
                    attrCurrent = if (key in recognized) "SKIPPED"
                        else SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
                    verdict = if (key in recognized) "VALID" else "INVALID",
                    verifiedBy = if (key in recognized) SelinuxRawContextSource.CONTEXT_NODE
                        else SelinuxRawContextSource.NONE,
                )
            },
        )
    }

    private fun evaluate(
        raw: SelinuxDirtySepolicyRawSnapshot = raw(),
        carrier: SelinuxContextValiditySnapshot = this.carrier,
        status: SelinuxStatusHeader? = oldStatus,
        release: String? = "5.15.148-android",
        isUserBuild: Boolean = true,
    ) = SelinuxDirtySepolicyCompatibility.evaluate(carrier, raw, status, isUserBuild, release)

    @Test fun `both original kernel startup epochs are accepted`() {
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.OK, evaluate().verdict)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.OK,
            evaluate(status = newStatus, release = "6.10.2").verdict)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.OK,
            evaluate(status = newStatus, release = "7.1.0").verdict)
    }

    @Test fun `uid context PID and proc self identity follow original preflight errors`() {
        for (candidate in listOf(
            carrier.copy(failureReason = "UID mismatch: 111 != app uid 222"),
            carrier.copy(selinuxEnabled = false),
            carrier.copy(selinuxEnabled = null),
            carrier.copy(carrierContext = "u:r:untrusted_app:s0"),
            carrier.copy(pidContextMatchesCurrent = false),
            carrier.copy(pidContextMatchesCurrent = null),
            carrier.copy(procSelfContextMatchesCurrent = false),
            carrier.copy(procSelfContextMatchesCurrent = null),
        )) {
            assertEquals(candidate.toString(), SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
                evaluate(carrier = candidate).verdict)
        }
    }

    @Test fun `setcurrent and check context failure never become clean`() {
        for (edge in edges.take(2)) {
            val result = evaluate(raw = raw(missingEdges = setOf(edge)))
            assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.INCONCLUSIVE, result.verdict)
            val broken = evaluate(raw = raw(malformedEdges = setOf(edge)))
            assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, broken.verdict)
            val denied = raw().copy(observations = raw().observations.map {
                if (it.query == edge) it.copy(outcome = "DENIED") else it
            })
            assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, evaluate(raw = denied).verdict)
        }
    }

    @Test fun `all original root context or access witnesses produce warnings`() {
        val cases = listOf(
            setOf("u:r:adbroot:s0"), setOf("u:r:magisk:s0"),
            setOf("u:object_r:magisk_file:s0"), setOf("u:r:ksu:s0"),
            setOf("u:object_r:ksu_file:s0"), setOf("u:object_r:lsposed_file:s0"),
            setOf("u:object_r:xposed_data:s0"), setOf("u:object_r:xposed_file:s0"),
        )
        for (context in cases) assertEquals(context.toString(),
            SelinuxDirtySepolicyCompatibilityVerdict.WARNING,
            evaluate(raw = raw(recognized = context)).verdict)
        for (edge in edges.drop(2)) assertEquals(edge,
            SelinuxDirtySepolicyCompatibilityVerdict.WARNING,
            evaluate(raw = raw(allowed = setOf(edge))).verdict)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.WARNING,
            evaluate(carrier = carrier.copy(selinuxEnforced = false)).verdict)
    }

    @Test fun `system server execmem and dex2oat remain upstream warnings despite Duck observation strength`() {
        for (edge in listOf(edges[2], edges[8], edges[7])) {
            val result = evaluate(raw = raw(allowed = setOf(edge)))
            assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.WARNING, result.verdict)
        }
    }

    @Test fun `shell su check applies only to user builds`() {
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.WARNING,
            evaluate(raw = raw(allowed = setOf(edges[3]))).verdict)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.OK,
            evaluate(raw = raw(allowed = setOf(edges[3])), isUserBuild = false).verdict)
    }

    @Test fun `OR short circuit ignores later missing edges`() {
        val result = evaluate(raw = raw(
            recognized = setOf("u:r:magisk:s0", "u:r:ksu:s0", "u:object_r:lsposed_file:s0",
                "u:object_r:xposed_data:s0"),
            missingEdges = setOf(edges[4], edges[5], edges[6], edges[7], edges[8]),
        ))
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.WARNING, result.verdict)
    }

    @Test fun `version error precedes status warnings and avd test`() {
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
            evaluate(status = oldStatus.copy(version = 2, enforcing = 0)).verdict)
        assertTrue(evaluate(status = oldStatus.copy(version = 2)).reasons.single().contains("unknown status version"))
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
            evaluate(status = null).verdict)
    }

    @Test fun `status fields noninitial baseline and avd seqno each warn`() {
        val cases = listOf(
            evaluate(status = oldStatus.copy(enforcing = 0)),
            evaluate(status = oldStatus.copy(denyUnknown = 0)),
            evaluate(status = oldStatus.copy(sequence = 4, policyload = 1)),
            evaluate(status = newStatus.copy(policyload = 2), release = "6.10.1"),
            evaluate(raw = raw(avdSeqno = 2)),
        )
        cases.forEach { assertEquals(it.toString(), SelinuxDirtySepolicyCompatibilityVerdict.WARNING, it.verdict) }
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
            evaluate(raw = raw(avdSeqno = null)).verdict)
    }

    @Test fun `unstable evidence cannot claim compatible clean result`() {
        val unstable = raw().copy(observations = raw().observations.mapIndexed { index, observation ->
            if (observation.query == edges[2] && index % 2 == 1) observation.copy(outcome = "ALLOWED")
            else observation
        })
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.INCONCLUSIVE,
            evaluate(raw = unstable).verdict)
    }

    @Test fun `original context IO failure cannot be recovered using Duck fallback verdict`() {
        val invalidFromAttr = raw().copy(contextChecks = raw().contextChecks.map {
            if (it.context == "u:r:adbroot:s0") it.copy(
                contextNode = "UNAVAILABLE:open errno=13",
                accessNode = "INVALID",
                attrCurrent = SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
                verdict = "INVALID",
            ) else it
        })
        val result = evaluate(raw = invalidFromAttr)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, result.verdict)
        assertTrue(result.reasons.single().contains("context node failed"))
    }

    @Test fun `original class zero IO failure cannot be recovered using Duck attr negative`() {
        val invalidFromAttr = raw().copy(contextChecks = raw().contextChecks.map {
            if (it.context == "u:r:adbroot:s0") it.copy(
                contextNode = "INVALID",
                accessNode = "UNAVAILABLE",
                attrCurrent = SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
                verdict = "INVALID",
            ) else it
        })
        val result = evaluate(raw = invalidFromAttr)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, result.verdict)
        assertTrue(result.reasons.single().contains("class=0 failed"))
    }

    @Test fun `a first layer IO failure cannot invalidate independent Duck positive`() {
        val positiveFromClassZero = raw().copy(
            contextChecks = raw().contextChecks.map {
                if (it.context == "u:r:adbroot:s0") it.copy(
                    contextNode = "UNAVAILABLE:open errno=13", accessNode = "VALID",
                    verdict = "VALID", verifiedBy = SelinuxRawContextSource.ACCESS_CLASS_ZERO,
                ) else it
            },
            recognizedContexts = listOf("u:r:adbroot:s0"),
        )
        assertTrue("u:r:adbroot:s0" in positiveFromClassZero.recognizedContexts)
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
            evaluate(raw = positiveFromClassZero).verdict)
    }

    @Test fun `insufficient fallback stage information must never imply original OK`() {
        val missing = raw().copy(contextChecks = raw().contextChecks.map {
            if (it.context == "u:r:adbroot:s0") it.copy(
                contextNode = "INVALID", accessNode = "SKIPPED",
                attrCurrent = SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL,
                verdict = "INVALID",
            ) else it
        })
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.INCONCLUSIVE,
            evaluate(raw = missing).verdict)
    }

    @Test fun `missing kernel release is upstream error and mixed raw epochs stay inconclusive`() {
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.ERROR,
            evaluate(release = null).verdict)
        val mixed = raw().copy(observations = raw().observations.mapIndexed { index, sample ->
            if (index == 5) sample.copy(response = "0 ffffffff 0 ffffffff 2 0")
            else sample.copy(response = "0 ffffffff 0 ffffffff 1 0")
        })
        assertEquals(SelinuxDirtySepolicyCompatibilityVerdict.INCONCLUSIVE,
            evaluate(raw = mixed).verdict)
    }
}
