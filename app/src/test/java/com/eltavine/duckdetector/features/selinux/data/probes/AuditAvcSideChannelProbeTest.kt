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
}
