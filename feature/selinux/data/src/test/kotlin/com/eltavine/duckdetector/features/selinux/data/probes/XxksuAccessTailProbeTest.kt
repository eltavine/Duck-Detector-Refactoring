/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */
package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class XxksuAccessTailProbeTest {
    /**
     * Native /access observations from the real Xiaomi 13 ABBA capture in
     * SelinuxHideAttrProbe/debug-results/xxlatest_parser_tail_abba_20261124_022415/.
     * The test fixtures retain each of the four captured rounds, byte counts,
     * write/read results, errno, and six-field AV responses. Only the
     * SELinuxAccessTail logcat prefix and unused research-only cases were
     * removed; the original `tail_ksu_missing_colon` name is mapped to
     * Duck's `tail_ksu_partial` name. The request prefix is reconstructed
     * from the captured self context and SELinux process class index.
     */
    private fun captured(name: String): String =
        requireNotNull(javaClass.getResourceAsStream("/xxksu_access_tail/$name")) {
            "Missing SELinuxFS /access capture fixture: $name"
        }.bufferedReader().use { it.readText() }

    @Test fun realXxksuHideOnCaptureMatchesParserScannerMismatch() {
        val result = XxksuAccessTailProbe.interpret(captured("hide_on.txt"))
        assertEquals(SelinuxOracle.XXKSU_ACCESS_TAIL, result.oracle)
        assertEquals("Ignored-tail rejection observed", result.status)
        assertEquals(false, result.isSecure)
        assertFalse(result.permissionDenied)
    }

    @Test fun realXxksuHideOffCaptureIsNotPositiveEvenWhenSeqnoChanges() {
        val result = XxksuAccessTailProbe.interpret(captured("hide_off.txt"))
        assertEquals("No ignored-tail rejection observed", result.status)
        assertNull(result.isSecure)
        assertFalse(result.permissionDenied)
    }

    private val context = "u:r:app_zygote:s0:c512,c768"
    private val prefix = context + " " + context + " 2"
    // The exact six-field form captured on fuxi / GKI 5.15 in the ON series.
    private val av = "3217f7d ffffffff 0 ffffffff 1 0"
    private val suffixes = linkedMapOf(
        "base" to "",
        "tail_inv" to " :inv:",
        "tail_ksu" to " :ksu:",
        "tail_inv_file" to " :inv_file:",
        "tail_ksu_file" to " :ksu_file:",
        "tail_ksu_partial" to " :ksuX",
    )
    private val allCases = suffixes.keys + "invalid_source"

    private fun raw(
        hiddenRejected: Boolean,
        override: (Int, String, String) -> String = { _, _, line -> line },
    ): String = buildString {
        appendLine("== xxksu SELinuxFS ignored access tail ==")
        appendLine("access_tail_pid=18489 uid=10743 carrier=" + context + " enforcing=1 seccomp=2")
        appendLine("access_tail_prefix=" + prefix)
        for (round in 0 until 4) {
            for (name in if (round % 2 == 1) allCases.reversed() else allCases) {
                val input = if (name == "invalid_source")
                    "u:r:__access_tail_absent__:s0 " + context + " 2"
                else prefix + suffixes.getValue(name)
                val size = input.toByteArray(Charsets.UTF_8).size
                val rejected = name == "invalid_source" || (hiddenRejected &&
                    (name == "tail_ksu" || name == "tail_ksu_file"))
                val line = "access_tail_case=" + name + " round=" + round +
                    " size=" + size + " open_errno=0" +
                    if (rejected) {
                        " write_ret=-1 write_errno=22 read_ret=-1 read_errno=0 response=[]"
                    } else {
                        " write_ret=" + size + " write_errno=0 read_ret=31 read_errno=0 response=[" + av + "]"
                    }
                appendLine(override(round, name, line))
            }
        }
        appendLine("access_tail_status=complete identity_unchanged=true")
    }

    @Test fun hideOnWithBothHiddenSuffixesRejectedIsStrongCandidate() {
        val result = XxksuAccessTailProbe.interpret(raw(hiddenRejected = true))
        assertEquals(SelinuxOracle.XXKSU_ACCESS_TAIL, result.oracle)
        assertEquals(false, result.isSecure)
        assertEquals("Ignored-tail rejection observed", result.status)
        assertTrue(result.details.orEmpty().contains("parser/scanner mismatch"))
    }

    @Test fun hideOffDoesNotProveCleanKernel() {
        val result = XxksuAccessTailProbe.interpret(raw(hiddenRejected = false))
        assertEquals("No ignored-tail rejection observed", result.status)
        assertNull(result.isSecure)
    }

    @Test fun failedPlaceboControlCannotBecomePositive() {
        val result = XxksuAccessTailProbe.interpret(raw(true) { round, name, line ->
            if (round == 1 && name == "tail_inv") line.replace("write_ret=", "write_ret=-1DEAD")
            else line
        })
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
    }

    @Test fun unrelatedHiddenPermissionErrorIsNotPositive() {
        val result = XxksuAccessTailProbe.interpret(raw(true) { round, name, line ->
            if (round == 2 && name == "tail_ksu_file") line.replace("write_errno=22", "write_errno=13")
            else line
        })
        assertEquals("Permission limited", result.status)
        assertNull(result.isSecure)
        assertTrue(result.permissionDenied)
    }

    @Test fun aSingleSuccessfulHiddenTailDoesNotCompleteTheSignal() {
        val result = XxksuAccessTailProbe.interpret(raw(true) { round, name, line ->
            if (round == 3 && name == "tail_ksu") {
                val size = (prefix + " :ksu:").length
                "access_tail_case=tail_ksu round=3 size=" + size +
                    " open_errno=0 write_ret=" + size +
                    " write_errno=0 read_ret=31 read_errno=0 response=[" + av + "]"
            } else line
        })
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
    }

    @Test fun differentSuccessfulAccessResponseIsInconclusive() {
        val result = XxksuAccessTailProbe.interpret(raw(true) { round, name, line ->
            if (round == 0 && name == "tail_inv_file")
                line.replace("response=[" + av + "]", "response=[f f 0 f 2 0]")
            else line
        })
        assertEquals("Inconclusive", result.status)
        assertNull(result.isSecure)
    }

    @Test fun missingDuplicateIdentityAndPermissionFailuresCannotBePositive() {
        assertEquals("Unavailable", XxksuAccessTailProbe.interpret(null).status)
        val sample = raw(true)
        assertEquals("Inconclusive", XxksuAccessTailProbe.interpret(
            sample.replace("access_tail_case=tail_ksu round=1", "access_tail_case=invalid_source round=1"),
        ).status)
        assertEquals("Inconclusive", XxksuAccessTailProbe.interpret(
            sample.substringBefore("access_tail_status=complete identity_unchanged=true"),
        ).status)
        assertEquals("Unavailable", XxksuAccessTailProbe.interpret(
            sample.replace("seccomp=2", "seccomp=0"),
        ).status)
        val denied = XxksuAccessTailProbe.interpret(
            sample.replace("open_errno=0 write_ret=-1", "open_errno=13 write_ret=-1"),
        )
        assertEquals("Permission limited", denied.status)
        assertNull(denied.isSecure)
        assertFalse(XxksuAccessTailProbe.interpret(
            sample.replace("access_tail_status=complete identity_unchanged=true",
                "access_tail_status=complete identity_unchanged=false"),
        ).isSecure == false)
    }
}
