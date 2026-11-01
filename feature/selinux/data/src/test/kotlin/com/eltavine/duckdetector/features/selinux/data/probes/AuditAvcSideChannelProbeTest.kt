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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AuditAvcSideChannelProbeTest {

    private val probe = AuditAvcSideChannelProbe()

    @Test
    fun `canonical avc denied line is reported as side channel`() {
        val result = probe.evaluate(
            """
                03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:123): avc: denied { getattr } for path="/proc/1/maps" dev="proc" ino=1 scontext=u:r:untrusted_app:s0:c123,c456 tcontext=u:r:init:s0 tclass=file permissive=0
            """.trimIndent(),
        )

        assertEquals(1, result.hits.size)
        assertEquals("AVC denial leak", result.hits.single().label)
        assertTrue(result.hits.single().value.startsWith("scontext="))
    }

    @Test
    fun `plain app log mentioning avc is ignored`() {
        val result = probe.evaluate(
            """
                03-19 12:00:00.000  1234  1234 I DuckDetector: avc denied string used in docs only
            """.trimIndent(),
        )

        assertTrue(result.hits.isEmpty())
    }

    @Test
    fun `non canonical avc line without type 1400 is ignored`() {
        val result = probe.evaluate(
            """
                03-19 12:00:00.000  1234  1234 W auditd  : avc: denied { getattr } for path="/proc/1/maps" scontext=u:r:untrusted_app:s0:c123,c456 tcontext=u:r:init:s0 tclass=file
            """.trimIndent(),
        )

        assertTrue(result.hits.isEmpty())
    }

    @Test
    fun `duplicate avc lines are deduplicated`() {
        val line =
            """03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:123): avc: denied { open } for comm="su" path="/proc/1/mem" scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0"""
        val result = probe.evaluate(
            """
                $line
                $line
            """.trimIndent(),
        )

        assertEquals(1, result.hits.size)
        assertEquals("comm=su", result.hits.single().value)
    }

    @Test
    fun `evaluate against references only matches same canonical avc`() {
        val output =
            """
                03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:123): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_file:s0 tclass=file permissive=0
                03-19 12:00:01.000  1234  1234 W auditd  : type=1400 audit(0.0:124): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0
            """.trimIndent()
        val reference = probe.parseCanonicalSignature(
            """type=1400 audit(0.0:5): avc: denied { write } for scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_file:s0 tclass=file permissive=0""",
        )

        val result = probe.evaluateAgainstReferences(output, listOfNotNull(reference))

        assertEquals(1, result.hits.size)
        assertTrue(result.hits.single().detail.orEmpty().contains("system_file"))
    }

    @Test
    fun `suspicious su actor is separated from generic avc leaks`() {
        val result = probe.evaluateSuspiciousActors(
            """
                03-19 12:00:00.000  1234  1234 W auditd  : type=1400 audit(0.0:123): avc: denied { open } for comm="su" path="/system/bin/su" scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0
                03-19 12:00:01.000  1234  1234 W auditd  : type=1400 audit(0.0:124): avc: denied { open } for comm="ping" path="/proc/1/maps" scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0
            """.trimIndent(),
        )

        assertEquals(1, result.hits.size)
        assertEquals("su-related AVC", result.hits.single().label)
        assertEquals("comm=su", result.hits.single().value)
    }

    @Test
    fun `self generated data adb avc is excluded`() {
        val result = probe.evaluateSuspiciousActors(
            """
                08-14 14:00:00.000 1234 1234 W auditd : type=1400 audit(0.0:123): avc: denied { search } for comm="DefaultDispatch" name="adb" dev="dm-57" ino=154 scontext=u:r:untrusted_app:s0:c123,c257,c512,c768 tcontext=u:object_r:system_data_root_file:s0 tclass=dir permissive=0 app=com.eltavine.duckdetector
            """.trimIndent(),
        )

        assertTrue(result.hits.isEmpty())
    }

    @Test
    fun `ordinary app getattr data adb is not a su actor even without app marker`() {
        val result = probe.evaluateSuspiciousActors(
            """10-25 00:37:00.000 2590 2590 I auditd : type=1400 audit(0.0:98142): avc: denied { getattr } for comm="DefaultDispatch" path="/data/adb" dev="dm-53" ino=343 scontext=u:r:untrusted_app:s0:c139,c258,c512,c768 tcontext=u:object_r:system_data_root_file:s0 tclass=dir permissive=0""",
        )
        assertTrue(result.hits.isEmpty())
    }

    @Test
    fun `target path or name alone must not identify a root actor`() {
        val lines = listOf(
            """comm="DefaultDispatch" path="/data/adb/modules/auditpatch/module.prop""",
            """comm="DefaultDispatch" name="adb""",
            """comm="DefaultDispatch" path="/data/adb/ksud""",
            """comm="DefaultDispatch" path="/system/xbin/su""",
            """comm="DefaultDispatch" exe="/system/bin/toybox" path="/data/adb/magiskd""",
            """comm="DefaultDispatch" exe="/data/local/tmp/fake-ksud""",
        ).mapIndexed { index, fields ->
            """type=1400 audit(0.0:$index): avc: denied { getattr } for $fields scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:object_r:system_data_root_file:s0 tclass=file permissive=0"""
        }.joinToString("\n")

        assertTrue(probe.evaluateSuspiciousActors(lines).hits.isEmpty())
    }

    @Test
    fun `actual root executable remains a hit and takes precedence over unrelated comm`() {
        val result = probe.evaluateSuspiciousActors(
            """type=1400 audit(0.0:202): avc: denied { read } for comm="DefaultDispatch" exe="/data/adb/ksud" path="/proc/1/maps" scontext=u:r:untrusted_app:s0:c1,c2 tcontext=u:r:init:s0 tclass=file permissive=0""",
        )
        assertEquals(1, result.hits.size)
        assertEquals("exe=/data/adb/ksud", result.hits.single().value)
    }

    @Test
    fun `actual root process remains a hit when target is data adb`() {
        val result = probe.evaluateSuspiciousActors(
            """type=1400 audit(0.0:203): avc: denied { getattr } for comm="ksud" path="/data/adb" scontext=u:r:su:s0 tcontext=u:object_r:system_data_root_file:s0 tclass=dir permissive=0""",
        )
        assertEquals(1, result.hits.size)
        assertEquals("comm=ksud", result.hits.single().value)
    }

    @Test
    fun `self app marker does not hide suspicious actor`() {
        val result = probe.evaluateSuspiciousActors(
            """
                08-14 14:00:00.000 1234 1234 W auditd : type=1400 audit(0.0:124): avc: denied { open } for comm="su" name="adb" dev="dm-57" ino=154 scontext=u:r:untrusted_app:s0:c123,c257,c512,c768 tcontext=u:object_r:system_data_root_file:s0 tclass=dir permissive=0 app=com.eltavine.duckdetector
            """.trimIndent(),
        )

        assertEquals(1, result.hits.size)
        assertEquals("comm=su", result.hits.single().value)
    }
}
