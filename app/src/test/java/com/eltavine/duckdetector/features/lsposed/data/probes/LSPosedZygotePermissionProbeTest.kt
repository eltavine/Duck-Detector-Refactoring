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

package com.eltavine.duckdetector.features.lsposed.data.probes

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LSPosedZygotePermissionProbeTest {

    private val probe = LSPosedZygotePermissionProbe()

    @Test
    fun `clean internet gid audit stays all clear`() {
        val result = probe.evaluate(
            grantedPermissions = setOf(android.Manifest.permission.INTERNET),
            statusContent = """
                Name:   com.eltavine.duckdetector
                Groups: 3003 9997
            """.trimIndent(),
        )

        assertTrue(result.available)
        assertEquals(1, result.auditedGrantCount)
        assertEquals(0, result.mismatchCount)
        assertTrue(result.signals.isEmpty())
        assertTrue(result.detail.contains("INTERNET"))
    }

    @Test
    fun `missing expected gid reports restriction`() {
        val result = probe.evaluate(
            grantedPermissions = setOf(android.Manifest.permission.INTERNET),
            statusContent = """
                Name:   com.eltavine.duckdetector
                Groups: 9997
            """.trimIndent(),
        )

        assertTrue(result.available)
        assertEquals(1, result.auditedGrantCount)
        assertEquals(1, result.mismatchCount)
        assertEquals(1, result.signals.size)
        assertEquals("INTERNET GID mismatch", result.signals.single().label)
        assertTrue(result.signals.single().detail.contains("INET_GID"))
    }

    @Test
    fun `multi gid rule requires every expected gid`() {
        val result = probe.evaluate(
            grantedPermissions = setOf("android.permission.DIAGNOSTIC"),
            statusContent = """
                Name:   com.eltavine.duckdetector
                Groups: 1004
            """.trimIndent(),
        )

        assertEquals(1, result.mismatchCount)
        assertTrue(result.signals.single().detail.contains("DIAG_GID"))
    }

    @Test
    fun `missing groups line downgrades to support`() {
        val result = probe.evaluate(
            grantedPermissions = setOf(android.Manifest.permission.INTERNET),
            statusContent = """
                Name:   com.eltavine.duckdetector
                State:  R (running)
            """.trimIndent(),
        )

        assertFalse(result.available)
        assertEquals(1, result.auditedGrantCount)
        assertEquals(0, result.mismatchCount)
        assertTrue(result.signals.isEmpty())
    }

    @Test
    fun `no mapped granted permissions returns no coverage`() {
        val result = probe.evaluate(
            grantedPermissions = setOf(android.Manifest.permission.ACCESS_NETWORK_STATE),
            statusContent = """
                Name:   com.eltavine.duckdetector
                Groups: 3003
            """.trimIndent(),
        )

        assertTrue(result.available)
        assertEquals(0, result.auditedGrantCount)
        assertEquals(0, result.mismatchCount)
        assertTrue(result.signals.isEmpty())
    }
}
