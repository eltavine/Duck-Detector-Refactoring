// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.native.NativeLibraryHandle
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAvcLookupPayloadTest {
    private val collected = SelinuxAvcLookupSnapshot(
        state = SelinuxAvcLookupState.COLLECTED, step = SelinuxAvcLookupStep.FINISHED,
        cpu = 2, cpuRow = 2, cpuRows = 8, possibleCpus = 8, pairs = 128, rounds = 4, writesPerBatch = 4096,
        batchesA = List(4) { 4102L }, batchesB = List(4) { 8198L },
        medianANs = 301, medianBNs = 201, medianDeltaNs = 100, childEnd = SelinuxAvcLookupChildEnd.EXITED,
    )

    /** The bridge's output for a collected run, in its key order; see test_avc_lookup_native.py. */
    private fun nativePayload(overrides: Map<String, String?> = emptyMap()): String {
        val fields = linkedMapOf<String, String?>(
            "SCHEMA" to "1", "STATE" to "COLLECTED", "STEP" to "FINISHED", "ERRNO" to "0",
            "UNEXPECTED_PAYLOAD" to "NONE", "UNEXPECTED_RETURNED" to "0", "IDENTITY_CHANGED" to "0",
            "CPU" to "2", "CPU_ROW" to "2", "CPU_ROWS" to "8", "POSSIBLE_CPUS" to "8",
            "PAIRS" to "128", "ROUNDS" to "4", "WRITES" to "4096",
            "BATCH_A" to "4102,4102,4102,4102", "BATCH_B" to "8198,8198,8198,8198",
            "MEDIAN_A_NS" to "301", "MEDIAN_B_NS" to "201", "MEDIAN_DELTA_NS" to "100",
            "CHILD_END" to "EXITED", "CHILD_EXIT" to "0", "CHILD_SIGNAL" to "0", "CHILD_ERRNO" to "0",
        )
        fields.putAll(overrides)
        return fields.entries.filter { it.value != null }.joinToString("") { "${it.key}=${it.value}\n" }
    }

    @Test fun `native payload decodes and survives the retained carrier record`() {
        assertEquals(collected, SelinuxAvcLookupPayloadCodec.decode(nativePayload()))
        val retained = SelinuxContextValidityPayloadCodec.encode(SelinuxContextValiditySnapshot(avcLookup = collected))
        assertEquals(collected, SelinuxContextValidityBridge().parse(retained).avcLookup)
    }

    @Test fun `every outcome keeps its step errno and child record through a round trip`() {
        val zeros = List(4) { 0L }
        listOf(
            collected.copy(state = SelinuxAvcLookupState.TIMING_ONLY, step = SelinuxAvcLookupStep.STATS, errno = 2,
                rounds = 0, cpuRows = 0, batchesA = zeros, batchesB = zeros),
            collected.copy(state = SelinuxAvcLookupState.TIMING_ONLY, step = SelinuxAvcLookupStep.COUNTING, errno = 18,
                rounds = 1, batchesA = listOf(4102L, 0, 0, 0), batchesB = listOf(4102L, 0, 0, 0)),
            SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.PERMISSION_LIMITED, step = SelinuxAvcLookupStep.CONTROLS,
                errno = 13, unexpectedPayload = SelinuxAvcLookupPayload.A, unexpectedReturned = -1,
                writesPerBatch = 4096, batchesA = zeros, batchesB = zeros, childEnd = SelinuxAvcLookupChildEnd.EXITED),
            collected.copy(state = SelinuxAvcLookupState.INCONCLUSIVE, childEnd = SelinuxAvcLookupChildEnd.TIMED_OUT),
            collected.copy(state = SelinuxAvcLookupState.INCONCLUSIVE, step = SelinuxAvcLookupStep.IDENTITY,
                identityChanged = true),
            SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.UNSUPPORTED, failureReason = "UID mismatch\nsecond line"),
            SelinuxAvcLookupSnapshot(),
        ).forEach { snapshot ->
            assertEquals(snapshot, SelinuxAvcLookupPayloadCodec.decode(SelinuxAvcLookupPayloadCodec.encode(snapshot)))
            val retained = SelinuxContextValidityPayloadCodec.encode(SelinuxContextValiditySnapshot(avcLookup = snapshot))
            assertEquals(snapshot, SelinuxContextValidityBridge().parse(retained).avcLookup)
        }
    }

    @Test fun `malformed and incomplete records become unavailable without discarding the carrier record`() {
        listOf(
            nativePayload(mapOf("SCHEMA" to "2")),
            nativePayload(mapOf("STATE" to "DETECTED")),
            nativePayload() + "ERRNO=0\n",
            nativePayload() + "a line without a key\n",
            nativePayload(mapOf("BATCH_A" to "4102,4102,4102")),
            nativePayload(mapOf("BATCH_B" to "8198,8198,8198,4294967296")),
            nativePayload(mapOf("BATCH_A" to null)),
            nativePayload(mapOf("ERRNO" to "-1")),
            nativePayload(mapOf("CHILD_END" to "TIMED_OUT")),
            nativePayload(mapOf("CHILD_EXIT" to "1")),
            nativePayload(mapOf("CHILD_END" to "KILLED")),
            nativePayload(mapOf("ROUNDS" to "3")),
            nativePayload(mapOf("PAIRS" to "127")),
            nativePayload(mapOf("WRITES" to "1024")),
            nativePayload(mapOf("CPU_ROW" to "8")),
            nativePayload(mapOf("POSSIBLE_CPUS" to "7")),
            nativePayload(mapOf("UNEXPECTED_PAYLOAD" to "A")),
            nativePayload(mapOf("IDENTITY_CHANGED" to "1")),
            nativePayload(mapOf("STEP" to "COUNTING")),
            nativePayload(mapOf("STATE" to "TIMING_ONLY", "STEP" to "TIMING", "ERRNO" to "2")),
            nativePayload(mapOf("STATE" to "TIMING_ONLY", "STEP" to "STATS", "ERRNO" to "0")),
        ).forEach { raw ->
            val snapshot = SelinuxAvcLookupPayloadCodec.decode(raw)
            assertEquals(raw, SelinuxAvcLookupState.UNAVAILABLE, snapshot.state)
            assertTrue(raw, snapshot.failureReason!!.startsWith("AVC lookup payload was rejected"))
        }
        val carrier = SelinuxContextValidityBridge().parse(
            "AVAILABLE=1\nCARRIER_CONTEXT=u:r:app_zygote:s0\nAPP_ZYGOTE_AVC_LOOKUP=SCHEMA=2\n",
        )
        assertTrue(carrier.available)
        assertEquals("u:r:app_zygote:s0", carrier.carrierContext)
        assertEquals(SelinuxAvcLookupState.UNAVAILABLE, carrier.avcLookup.state)
    }

    @Test fun `native fallback and legacy carrier records stay explicit`() {
        assertEquals(
            SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.UNAVAILABLE, failureReason = "Native AVC lookup collection failed."),
            SelinuxAvcLookupPayloadCodec.decode("SCHEMA=1\nSTATE=UNAVAILABLE\nFAILURE_REASON=Native AVC lookup collection failed.\n"),
        )
        assertEquals(SelinuxAvcLookupState.NOT_COLLECTED, SelinuxContextValidityBridge().parse("AVAILABLE=1\n").avcLookup.state)
    }

    @Test fun `an unloaded native library is unavailable with its reason`() {
        val snapshot = SelinuxAvcLookupProbe(NativeSnapshotCollector(object : NativeLibraryHandle {
            override val isLoaded = false
            override val loadFailureDetail = "dlopen failed"
        })).inspect()
        assertEquals(SelinuxAvcLookupState.UNAVAILABLE, snapshot.state)
        assertTrue(snapshot.failureReason!!.contains("dlopen failed"))
    }

    @Test fun `a later preload failure keeps a finished experiment`() {
        val snapshot = SelinuxContextValidityBridge().parse(
            SelinuxContextValidityPreload().fallbackPayload("later step failed", avcLookup = collected),
        )
        assertEquals(collected, snapshot.avcLookup)
        assertEquals("later step failed", snapshot.failureReason)
    }

    @Test fun `a failed carrier gate skips the child and keeps the gate reason`() {
        val snapshot = SelinuxContextValidityPreload.augmentPreloadSnapshot(
            baseSnapshot = SelinuxContextValiditySnapshot(),
            currentUid = 10001,
            appUid = 10000,
            isUserBuild = true,
            accessCheckBlockReason = null,
            inspectProcAttrCurrent = { error("the attr/current child must not run") },
            inspectAvcLookup = { error("the AVC lookup child must not run") },
            inspectPolicyloadSeqno = { error("the seqno oracle must not run") },
            checkAccess = { _, _, _, _ -> null },
        )
        assertEquals(
            SelinuxAvcLookupSnapshot(state = SelinuxAvcLookupState.UNSUPPORTED, failureReason = "UID mismatch: 10001 != app uid 10000"),
            snapshot.avcLookup,
        )
    }
}
