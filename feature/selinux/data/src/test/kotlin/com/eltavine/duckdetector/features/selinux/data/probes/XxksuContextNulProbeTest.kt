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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XxksuContextNulProbeTest {
    // Four original rounds from the controlled Xiaomi 13 ON/OFF capture.
    // Research logcat converted a terminal response NUL to a visible space;
    // normalize that display-only space to Duck's actual native I/O format.
    private fun capture(name: String) =
        requireNotNull(javaClass.getResourceAsStream("/xxksu_context_nul/$name"))
            .bufferedReader().use { it.readText() }

    private fun combinedCarrierCapture(name: String): String {
        val access = requireNotNull(
            javaClass.getResourceAsStream("/xxksu_access_tail/$name"),
        ).bufferedReader().use { it.readText() }
        val contextLines = capture(name).lineSequence().filter {
            it.startsWith("context_nul_")
        }.joinToString("\n")
        return access.replace(
            "access_tail_status=complete identity_unchanged=true",
            "$contextLines\naccess_tail_status=complete identity_unchanged=true",
        )
    }

    @Test fun `combined native report keeps both previously independent parser results`() {
        val on = combinedCarrierCapture("hide_on.txt")
        assertEquals(false, XxksuAccessTailProbe.interpret(on).isSecure)
        assertEquals(false, XxksuContextNulProbe.interpret(on).isSecure)
        val off = combinedCarrierCapture("hide_off.txt")
        assertEquals("No ignored-tail rejection observed",
            XxksuAccessTailProbe.interpret(off).status)
        assertEquals("No NUL-tail rejection observed",
            XxksuContextNulProbe.interpret(off).status)
    }

    @Test fun `real hide ON capture is a four round NUL tail mismatch`() {
        val result = XxksuContextNulProbe.interpret(capture("hide_on.txt"))
        assertEquals(SelinuxOracle.XXKSU_CONTEXT_NUL, result.oracle)
        assertEquals("NUL-tail rejection observed", result.status)
        assertEquals(false, result.isSecure)
        assertFalse(result.permissionDenied)
        assertTrue(result.details.orEmpty().contains("not independent"))
    }

    @Test fun `real hide OFF capture is informational and not clean proof`() {
        val result = XxksuContextNulProbe.interpret(capture("hide_off.txt"))
        assertEquals("No NUL-tail rejection observed", result.status)
        assertNull(result.isSecure)
        assertFalse(result.permissionDenied)
    }

    @Test fun `permission denial cannot be a positive NUL tail signal`() {
        val raw = capture("hide_on.txt").replaceFirst(
            "context_nul_case=context_nul_ksu round=0 size=34 open_errno=0",
            "context_nul_case=context_nul_ksu round=0 size=34 open_errno=13",
        )
        val result = XxksuContextNulProbe.interpret(raw)
        assertEquals("Permission limited", result.status)
        assertTrue(result.permissionDenied)
        assertNull(result.isSecure)
    }

    @Test fun `failed valid context control cannot signal danger`() {
        val raw = capture("hide_on.txt").replaceFirst(
            "context_nul_case=context_nul_inv round=0 size=34 open_errno=0 write_ret=34 write_errno=0",
            "context_nul_case=context_nul_inv round=0 size=34 open_errno=0 write_ret=-1 write_errno=22",
        )
        val result = XxksuContextNulProbe.interpret(raw)
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
    }

    @Test fun `canonical output must equal the current exact context`() {
        val raw = capture("hide_on.txt").replaceFirst(
            "response=[u:r:app_zygote:s0:c512,c768]",
            "response=[u:r:app_zygote:s0:c512,c769]",
        )
        val result = XxksuContextNulProbe.interpret(raw)
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
    }

    @Test fun `a mixed hidden outcome is inconclusive`() {
        val raw = capture("hide_on.txt").replaceFirst(
            "context_nul_case=context_nul_ksu round=0 size=34 open_errno=0 write_ret=-1 write_errno=22 read_ret=-1 read_errno=0 response=[]",
            "context_nul_case=context_nul_ksu round=0 size=34 open_errno=0 write_ret=34 write_errno=0 read_ret=28 read_errno=0 response=[u:r:app_zygote:s0:c512,c768]",
        )
        val result = XxksuContextNulProbe.interpret(raw)
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
    }

    @Test fun `missing or duplicate rounds cannot signal danger`() {
        val raw = capture("hide_on.txt")
        val case = raw.lineSequence().first {
            it.startsWith("context_nul_case=context_nul_ksu_file round=3 ")
        }
        assertEquals("Inconclusive",
            XxksuContextNulProbe.interpret(raw.replace("$case\n", "")).status)
        assertEquals("Inconclusive",
            XxksuContextNulProbe.interpret(raw + case + "\n").status)
    }

    @Test fun `incomplete or previous version report stays unavailable or inconclusive`() {
        val raw = capture("hide_on.txt")
        assertEquals("Inconclusive",
            XxksuContextNulProbe.interpret(raw.replace("context_nul_status=complete\n", "")).status)
        assertEquals("Inconclusive",
            XxksuContextNulProbe.interpret(
                raw.replace("access_tail_status=complete identity_unchanged=true",
                    "access_tail_status=complete identity_unchanged=false"),
            ).status)
        assertEquals("Unavailable",
            XxksuContextNulProbe.interpret(
                "access_tail_pid=18489 uid=10743 carrier=u:r:app_zygote:s0:c512,c768 enforcing=1 seccomp=2\n",
            ).status)
    }
}
