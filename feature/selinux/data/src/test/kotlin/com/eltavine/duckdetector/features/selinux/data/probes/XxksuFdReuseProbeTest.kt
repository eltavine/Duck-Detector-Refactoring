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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XxksuFdReuseProbeTest {
    private val carrier = "u:r:app_zygote:s0:c512,c768"

    private fun record(first: String, second: String, open: Int = 0) =
        "open_errno=$open first_ret=$first second_ret=$second"

    private fun raw(
        domain: String,
        domainInvalid: String,
        file: String,
        fileInvalid: String,
        preflight: String = "PASS",
        invalidControl: String = record("-1 errno=22", "-1 errno=16"),
        nativeVerdict: String = "EARLY_RETURN_CANDIDATE",
    ): String = """
        == SELinuxFS same-FD transaction state ==
        fd_reuse_pid=30309 fd_reuse_uid=10743
        fd_reuse_carrier=$carrier read_errno=0
        fd_reuse_case=preflight_valid_valid ${record("27 errno=0", "-1 errno=16")}
        fd_reuse_case=preflight_invalid_invalid ${record("-1 errno=22", "-1 errno=16")}
        fd_reuse_preflight=$preflight
        fd_reuse_case=invalid_to_valid $invalidControl
        fd_reuse_case=xxksu_to_valid $domain
        fd_reuse_case=xxksu_to_invalid $domainInvalid
        fd_reuse_case=xxksu_file_to_valid $file
        fd_reuse_case=xxksu_file_to_invalid $fileInvalid
        fd_reuse_verdict=$nativeVerdict
    """.trimIndent()

    private val earlyValid = record("-1 errno=22", "27 errno=0")
    private val earlyInvalid = record("-1 errno=22", "-1 errno=22")
    private val stockInvalid = record("-1 errno=22", "-1 errno=16")

    @Test fun hideOnBothHiddenTypesIsDanger() {
        val result = XxksuFdReuseProbe.interpret(raw(earlyValid, earlyInvalid, earlyValid, earlyInvalid))
        assertEquals(SelinuxOracle.XXKSU_FD_REUSE, result.oracle)
        assertEquals(false, result.isSecure)
        assertTrue(result.status.contains("Early return observed"))
        assertTrue(result.details.orEmpty().contains("xxksu_to_valid"))
        assertTrue(result.details.orEmpty().contains("A complete same-FD early-return signature was observed"))
    }

    @Test fun hideOffWithLiveKsuTypesIsNotObservedNotSecure() {
        val result = XxksuFdReuseProbe.interpret(raw(
            record("10 errno=0", "-1 errno=16"),
            record("10 errno=0", "-1 errno=16"),
            record("22 errno=0", "-1 errno=16"),
            record("22 errno=0", "-1 errno=16"),
            nativeVerdict = "NO_BYPASS_OBSERVED",
        ))
        assertEquals("No FD bypass observed", result.status)
        assertNull(result.isSecure)
        assertTrue(result.details.orEmpty().contains("No same-FD early-return signature was observed"))
        assertFalse(result.details.orEmpty().contains("A complete same-FD early-return signature was observed"))
    }

    @Test fun stockGkiBothInvalidTypesAreNotObserved() {
        val result = XxksuFdReuseProbe.interpret(raw(
            stockInvalid, stockInvalid, stockInvalid, stockInvalid,
            nativeVerdict = "NO_BYPASS_OBSERVED",
        ))
        assertEquals("No FD bypass observed", result.status)
        assertNull(result.isSecure)
        assertFalse(result.details.orEmpty().contains("A complete same-FD early-return signature was observed"))
    }

    @Test fun oneHiddenTypeIsStillEvidenceWithOtherPathControlled() {
        val result = XxksuFdReuseProbe.interpret(raw(
            earlyValid, earlyInvalid, stockInvalid, stockInvalid,
        ))
        assertEquals(false, result.isSecure)
        assertTrue(result.status.contains("xxksu"))
    }

    @Test fun `a confirmed domain positive remains danger when file candidate has unknown errno`() {
        val unknown = record("-1 errno=13", "-1 errno=13")
        val result = XxksuFdReuseProbe.interpret(raw(
            earlyValid, earlyInvalid, unknown, unknown,
        ))
        assertEquals(false, result.isSecure)
        assertEquals("Early return observed (xxksu)", result.status)
        assertTrue(result.details.orEmpty().contains("xxksu_file_to_valid: first=-1/errno=13"))
    }

    @Test fun `a confirmed file positive remains danger when domain candidate has unknown errno`() {
        val unknown = record("-1 errno=5", "-1 errno=5")
        val result = XxksuFdReuseProbe.interpret(raw(
            unknown, unknown, earlyValid, earlyInvalid,
        ))
        assertEquals(false, result.isSecure)
        assertEquals("Early return observed (xxksu_file)", result.status)
    }

    @Test fun `native early return claim without supporting write records is not danger`() {
        val result = XxksuFdReuseProbe.interpret(raw(
            stockInvalid, stockInvalid, stockInvalid, stockInvalid,
            nativeVerdict = "EARLY_RETURN_CANDIDATE",
        ))
        assertEquals("No FD bypass observed", result.status)
        assertNull(result.isSecure)
        assertTrue(result.details.orEmpty().contains("Native summary differs"))
        assertFalse(result.details.orEmpty().contains("A complete same-FD early-return signature was observed"))
    }

    @Test fun `verified early return remains danger even when native summary conflicts`() {
        val result = XxksuFdReuseProbe.interpret(raw(
            earlyValid, earlyInvalid, stockInvalid, stockInvalid,
            nativeVerdict = "NO_BYPASS_OBSERVED",
        ))
        assertEquals(false, result.isSecure)
        assertEquals("Early return observed (xxksu)", result.status)
        assertTrue(result.details.orEmpty().contains("Native summary differs"))
    }

    @Test fun `unknown candidate errno without any confirmed positive is inconclusive`() {
        val unknown = record("-1 errno=13", "-1 errno=13")
        val result = XxksuFdReuseProbe.interpret(raw(
            stockInvalid, stockInvalid, unknown, unknown,
            nativeVerdict = "INCONCLUSIVE",
        ))
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
        assertTrue(result.details.orEmpty().contains("No complete early-return signature was established"))
    }

    @Test fun controlFailureCannotMakeADangerVerdict() {
        val result = XxksuFdReuseProbe.interpret(raw(
            earlyValid, earlyInvalid, earlyValid, earlyInvalid,
            invalidControl = record("-1 errno=22", "27 errno=0"),
        ))
        assertNull(result.isSecure)
        assertEquals("Inconclusive", result.status)
    }

    @Test fun missingCarrierAndContradictoryCasesAreInconclusive() {
        assertEquals("Unavailable", XxksuFdReuseProbe.interpret(null).status)
        val conflict = raw(earlyValid, earlyInvalid, earlyValid, earlyInvalid)
            .replace("fd_reuse_pid=30309", "fd_reuse_pid=0")
        assertEquals("Unavailable", XxksuFdReuseProbe.interpret(conflict).status)
        val duplicated = raw(earlyValid, earlyInvalid, earlyValid, earlyInvalid) +
            "\nfd_reuse_case=xxksu_to_valid $earlyValid"
        assertEquals("Inconclusive", XxksuFdReuseProbe.interpret(duplicated).status)
        assertFalse(XxksuFdReuseProbe.interpret(duplicated).isSecure == false)
    }
}
