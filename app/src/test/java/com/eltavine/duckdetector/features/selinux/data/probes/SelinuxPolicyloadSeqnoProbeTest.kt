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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxPolicyloadSeqnoProbeTest {

    private val probe = SelinuxPolicyloadSeqnoProbe()

    @Test
    fun `matching status policyload and access seqno is clean`() {
        val result = probe.interpret(
            status = status(sequence = 12, policyload = 9),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.CLEAN, result.state)
        assertTrue(result.available)
        assertTrue(result.probeAttempted)
        assertEquals(12L, result.statusSequence)
        assertEquals(9L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
        assertEquals(2, result.processClass)
    }

    @Test
    fun `nonzero sequence with zero policyload and positive access seqno is suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 4, policyload = 0),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.SUSPICIOUS, result.state)
        assertTrue(result.available)
        assertEquals(0L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `fresh zero status page stays inconclusive instead of suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 0, policyload = 0),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.INCONCLUSIVE, result.state)
        assertTrue(result.available)
        assertEquals(0L, result.statusSequence)
        assertEquals(0L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `odd status sequence stays inconclusive instead of suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 5, policyload = 0),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.INCONCLUSIVE, result.state)
        assertTrue(result.available)
        assertEquals(5L, result.statusSequence)
        assertEquals(0L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `positive policyload mismatch is suspicious`() {
        val result = probe.interpret(
            status = status(sequence = 12, policyload = 7),
            access = access(seqno = 9),
        )

        assertEquals(SelinuxPolicyloadSeqnoState.SUSPICIOUS, result.state)
        assertTrue(result.available)
        assertEquals(7L, result.statusPolicyload)
        assertEquals(9L, result.accessSeqno)
    }

    @Test
    fun `metadata probe parses regular root readable selinuxfs files`() {
        val result = metadataProbe(
            stdout = """
                /sys/fs/selinux/status	0	8124
                /sys/fs/selinux/access	0	81b6
            """.trimIndent(),
        ).inspect()

        assertTrue(result.available)
        assertEquals(0, result.statusMetadata.uid)
        assertEquals("444", result.statusMetadata.mode)
        assertEquals(0x8124L, result.statusMetadata.rawMode)
        assertEquals("regular", result.statusMetadata.fileType)
        assertEquals(0, result.accessMetadata.uid)
        assertEquals("666", result.accessMetadata.mode)
        assertEquals(0x81b6L, result.accessMetadata.rawMode)
        assertEquals("regular", result.accessMetadata.fileType)
    }

    @Test
    fun `missing status metadata is a fail condition when access metadata parsed`() {
        val result = metadataProbe(
            stdout = "/sys/fs/selinux/access\t0\t81b6",
        ).inspect()

        assertTrue(result.available)
        assertEquals(false, result.statusMetadata.exists)
        assertTrue(result.failureReason.orEmpty().contains("/sys/fs/selinux/status missing"))
    }

    @Test
    fun `missing access metadata is a fail condition when status metadata parsed`() {
        val result = metadataProbe(
            stdout = "/sys/fs/selinux/status\t0\t8124",
        ).inspect()

        assertTrue(result.available)
        assertEquals(false, result.accessMetadata.exists)
        assertTrue(result.failureReason.orEmpty().contains("/sys/fs/selinux/access missing"))
    }

    @Test
    fun `non root selinux status owner is a fail condition`() {
        val result = metadataProbe(
            stdout = """
                /sys/fs/selinux/status	2000	8124
                /sys/fs/selinux/access	0	81b6
            """.trimIndent(),
        ).inspect()

        assertTrue(result.available)
        assertEquals(2000, result.statusMetadata.uid)
        assertTrue(result.failureReason.orEmpty().contains("uid=2000 expected=0"))
    }

    @Test
    fun `non 666 selinux access mode is a fail condition`() {
        val result = metadataProbe(
            stdout = """
                /sys/fs/selinux/status	0	8124
                /sys/fs/selinux/access	0	8124
            """.trimIndent(),
        ).inspect()

        assertTrue(result.available)
        assertEquals("444", result.accessMetadata.mode)
        assertEquals(0x8124L, result.accessMetadata.rawMode)
        assertTrue(result.failureReason.orEmpty().contains("mode=444 expected=666"))
    }

    @Test
    fun `non regular selinux status path is a fail condition`() {
        val result = metadataProbe(
            stdout = """
                /sys/fs/selinux/status	0	4124
                /sys/fs/selinux/access	0	81b6
            """.trimIndent(),
        ).inspect()

        assertTrue(result.available)
        assertEquals("directory", result.statusMetadata.fileType)
        assertTrue(result.failureReason.orEmpty().contains("type=directory expected=regular"))
    }

    @Test
    fun `stat timeout is unavailable not a metadata fail`() {
        val result = metadataProbe(
            stdout = "",
            timedOut = true,
        ).inspect()

        assertEquals(false, result.available)
        assertEquals(null, result.failureReason)
        assertTrue(result.unavailableReason.orEmpty().contains("stat command timed out"))
    }

    @Test
    fun `stat nonzero exit with parsed metadata still evaluates parsed metadata`() {
        val result = metadataProbe(
            stdout = """
                /sys/fs/selinux/status	0	8124
                /sys/fs/selinux/access	0	81b6
            """.trimIndent(),
            exitCode = 1,
            stderr = "No such file",
        ).inspect()

        assertTrue(result.available)
        assertEquals(null, result.failureReason)
        assertEquals(null, result.unavailableReason)
    }

    @Test
    fun `stat unparsable uid is unavailable not a metadata fail`() {
        val result = metadataProbe(
            stdout = """
                /sys/fs/selinux/status	root	8124
                /sys/fs/selinux/access	0	81b6
            """.trimIndent(),
        ).inspect()

        assertEquals(false, result.available)
        assertEquals(null, result.failureReason)
        assertTrue(result.unavailableReason.orEmpty().contains("stat uid was not numeric"))
    }

    private fun status(
        sequence: Long,
        policyload: Long,
    ) = SelinuxPolicyloadSeqnoProbe.SelinuxStatus(
        version = 1,
        sequence = sequence,
        enforcing = 1,
        policyload = policyload,
        denyUnknown = 0,
    )

    private fun access(
        seqno: Long,
    ) = SelinuxPolicyloadSeqnoProbe.AccessDecision(
        processClass = 2,
        seqno = seqno,
    )

    private fun metadataProbe(
        stdout: String,
        exitCode: Int? = 0,
        stderr: String = "",
        timedOut: Boolean = false,
    ): SelinuxPolicyloadSeqnoMetadataProbe {
        return SelinuxPolicyloadSeqnoMetadataProbe(
            statCommandRunner = SelinuxStatCommandRunner { command, timeoutSeconds ->
                assertEquals(
                    listOf(
                        "/system/bin/stat",
                        "-c",
                        "%n\t%u\t%f",
                        "/sys/fs/selinux/status",
                        "/sys/fs/selinux/access",
                    ),
                    command,
                )
                assertEquals(2L, timeoutSeconds)
                SelinuxStatCommandResult(
                    exitCode = exitCode,
                    stdout = stdout,
                    stderr = stderr,
                    timedOut = timedOut,
                )
            },
        )
    }
}
