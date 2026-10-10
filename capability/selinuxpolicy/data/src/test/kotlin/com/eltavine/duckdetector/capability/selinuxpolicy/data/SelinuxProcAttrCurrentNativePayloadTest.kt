// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.native.NativeLibraryHandle
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import org.junit.Assert.*
import org.junit.Test

class SelinuxProcAttrCurrentNativePayloadTest {
    private val targets = (0..8).map { index ->
        SelinuxProcAttrCurrentResult("label$index", "u:r:label$index:s0",
            if (index == 0) "CONTEXT_RECOGNIZED" else "NORMAL_EINVAL", "open_errno=0; write_errno=13")
    }
    private fun control(state: String) = SelinuxProcAttrCurrentResult("Controls", "", state, "raw\tcontrol\nerrors")
    private fun payload(rows: List<SelinuxProcAttrCurrentResult>) = "SCHEMA=1\n" +
        rows.joinToString("\n") { "RESULT=" + SelinuxProcAttrCurrentPayloadCodec.encode(it) }

    @Test fun `controlled native records survive escaping and preload snapshot round trip`() {
        val rows = listOf(control("CONTROLS_PASSED")) + targets
        assertEquals(rows, SelinuxProcAttrCurrentNativePayload.decode(payload(rows)))
        val snapshot = SelinuxContextValiditySnapshot(procAttrCurrentProbeAttempted = true, procAttrCurrentResults = rows)
        assertEquals(rows, SelinuxContextValidityBridge().parse(SelinuxContextValidityPayloadCodec.encode(snapshot)).procAttrCurrentResults)
        assertTrue(rows[1].detected())
        assertFalse(rows[2].detected())
    }

    @Test fun `unavailable control only is supported`() {
        val rows = listOf(control("UNAVAILABLE"))
        assertEquals(rows, SelinuxProcAttrCurrentNativePayload.decode(payload(rows)))
    }

    @Test fun `later preload failure preserves completed raw context writes`() {
        val rows = listOf(control("CONTROLS_PASSED")) + targets
        val snapshot = SelinuxContextValidityBridge().parse(
            SelinuxContextValidityPreload().fallbackPayload("later step failed", procAttrResults = rows),
        )
        assertTrue(snapshot.procAttrCurrentProbeAttempted)
        assertEquals(rows, snapshot.procAttrCurrentResults)
        assertEquals("later step failed", snapshot.failureReason)
    }

    @Test fun `incomplete contradictory duplicated unknown and oversized records are rejected`() {
        val rows = listOf(control("CONTROLS_PASSED")) + targets
        val invalid = listOf(payload(rows.dropLast(1)), payload(rows + rows.last()),
            payload(listOf(control("INCONCLUSIVE")) + targets),
            payload(listOf(control("UNKNOWN"))), payload(rows).replace("SCHEMA=1", "SCHEMA=2"),
            payload(rows).replace("NORMAL_EINVAL", "SUCCESS"), "SCHEMA=1\nOTHER=value",
            "SCHEMA=1\n" + "x".repeat(32_768))
        invalid.forEach { raw -> assertTrue(runCatching { SelinuxProcAttrCurrentNativePayload.decode(raw) }.isFailure) }
    }

    @Test fun `legacy error-only results do not become findings`() {
        listOf("SUCCESS", "DETECTED_NON_EINVAL", "DETECTED_SECURITY_EXCEPTION", "UNKNOWN")
            .forEach { assertFalse(targets.first().copy(outcomeClass = it).detected()) }
    }

    @Test fun `an unloaded native library yields one unavailable controls record and no candidates`() {
        val probe = SelinuxProcAttrCurrentProbe(NativeSnapshotCollector(object : NativeLibraryHandle {
            override val isLoaded = false
            override val loadFailureDetail = "dlopen failed"
        }))
        val rows = probe.inspect()
        assertEquals(1, rows.size)
        assertEquals(SelinuxProcAttrCurrentResult.CONTROL_LABEL, rows.single().label)
        assertEquals(SelinuxProcAttrCurrentResult.OUTCOME_UNAVAILABLE, rows.single().outcomeClass)
        assertTrue(rows.single().rawMessage.contains("dlopen failed"))
        assertEquals(rows, SelinuxProcAttrCurrentNativePayload.decode(payload(rows)))
    }
}
