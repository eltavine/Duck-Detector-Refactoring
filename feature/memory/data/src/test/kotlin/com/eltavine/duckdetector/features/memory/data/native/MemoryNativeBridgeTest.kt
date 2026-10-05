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

package com.eltavine.duckdetector.features.memory.data.native

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryNativeBridgeTest {

    private val bridge = MemoryNativeBridge()

    @Test
    fun `parse decodes escaped detail and booleans`() {
        val snapshot = bridge.parse(
            """
                AVAILABLE=1
                HOOK_CHECKS_RAN=1
                ENTRY_CHECKS_SUPPORTED=1
                GOT_PLT_HOOK=1
                MODIFIED_FUNCTION_COUNT=2
                HIGH_COUNT=1
                MEDIUM_COUNT=1
                FINDING=HOOK	GOT_PLT	Resolved address escaped expected module	HIGH	open resolved to /data/adb/modules/zygisk.so @ 0x1234
                FINDING=MAPS	SMAPS	Swapped executable pages	MEDIUM	/system/lib64/libc.so has 4 kB swapped executable pages\nVmFlags: rd ex mr mw me
            """.trimIndent(),
        )

        assertTrue(snapshot.available)
        assertTrue(snapshot.gotPltHook)
        assertTrue(snapshot.hookChecksRan)
        assertTrue(snapshot.entryChecksSupported)
        assertEquals(2, snapshot.modifiedFunctionCount)
        assertEquals(2, snapshot.findings.size)
        assertEquals("HOOK", snapshot.findings[0].section)
        assertTrue(snapshot.findings[1].detail.contains('\n'))
    }

    @Test
    fun `parse reads whether the vdso checks ran`() {
        val checked = bridge.parse("AVAILABLE=1\nVDSO_CHECKS_RAN=1\nVDSO_REMAPPED=1\n")
        val skipped = bridge.parse("AVAILABLE=1\nVDSO_CHECKS_RAN=0\n")

        assertTrue(checked.vdsoChecksRan)
        assertTrue(checked.vdsoRemapped)
        assertFalse(skipped.vdsoChecksRan)
    }

    @Test
    fun `parse keeps anonymous mappings apart from anonymous pages on system mappings`() {
        val snapshot = bridge.parse("AVAILABLE=1\nANONYMOUS_EXEC=0\nSYSTEM_ANONYMOUS_EXEC=1\n")

        assertFalse(snapshot.anonymousExec)
        assertTrue(snapshot.systemAnonymousExec)
    }

    @Test
    fun `parse reads whether copied system pages differ from their file or went unverified`() {
        val modified = bridge.parse(
            "AVAILABLE=1\nSYSTEM_ANONYMOUS_EXEC=1\nSYSTEM_COPY_MODIFIED=1\nSYSTEM_COPY_UNVERIFIED=0\n",
        )
        val unverified = bridge.parse(
            "AVAILABLE=1\nSYSTEM_ANONYMOUS_EXEC=1\nSYSTEM_COPY_MODIFIED=0\nSYSTEM_COPY_UNVERIFIED=1\n",
        )

        assertTrue(modified.systemCopyModified)
        assertFalse(modified.systemCopyUnverified)
        assertFalse(unverified.systemCopyModified)
        assertTrue(unverified.systemCopyUnverified)
    }

    @Test
    fun `parse falls back safely on blank raw data`() {
        val snapshot = bridge.parse("")

        assertFalse(snapshot.available)
        assertTrue(snapshot.findings.isEmpty())
        assertEquals(0, snapshot.modifiedFunctionCount)
    }
}
