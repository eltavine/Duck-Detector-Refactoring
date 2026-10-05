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

package com.eltavine.duckdetector.features.memory.data.repository

import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeFinding
import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeSnapshot
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MemoryRepositoryTest {

    private val repository = MemoryRepository()

    @Test
    fun `entry prologue is unsupported on ABIs without its instruction patterns`() {
        val methods = repository.buildMethods(
            MemoryNativeSnapshot(available = true, hookChecksRan = true, entryChecksSupported = false),
        )

        assertEquals(MemoryMethodOutcome.CLEAN, methods.first { it.label == "GOT/PLT resolution" }.outcome)
        val prologue = methods.first { it.label == "Entry prologue" }
        assertEquals("Unsupported ABI", prologue.summary)
        assertEquals(MemoryMethodOutcome.SUPPORT, prologue.outcome)
    }

    @Test
    fun `hook rows are unavailable when symbol resolution never ran`() {
        val methods = repository.buildMethods(MemoryNativeSnapshot(available = true, entryChecksSupported = true))

        listOf("GOT/PLT resolution", "Entry prologue").forEach { label ->
            assertEquals(label, MemoryMethodOutcome.SUPPORT, methods.first { it.label == label }.outcome)
        }
    }

    @Test
    fun `hook rows stay clean when both checks ran on a supported ABI`() {
        val methods = repository.buildMethods(
            MemoryNativeSnapshot(available = true, hookChecksRan = true, entryChecksSupported = true),
        )

        assertEquals(MemoryMethodOutcome.CLEAN, methods.first { it.label == "Entry prologue" }.outcome)
    }

    @Test
    fun `loader visibility stays clean and explains a process without a vdso`() {
        val loader = repository.buildMethods(MemoryNativeSnapshot(available = true, vdsoChecksRan = false))
            .first { it.label == "Loader visibility" }

        assertEquals(MemoryMethodOutcome.CLEAN, loader.outcome)
        assertTrue(loader.detail.contains("no vDSO"))
    }

    @Test
    fun `loader visibility reviews a remapped vdso once the checks ran`() {
        val loader = repository.buildMethods(
            MemoryNativeSnapshot(available = true, vdsoChecksRan = true, vdsoRemapped = true),
        ).first { it.label == "Loader visibility" }

        assertEquals(MemoryMethodOutcome.REVIEW, loader.outcome)
        assertTrue(loader.detail.contains("[vdso] view"))
    }

    @Test
    fun `sanitizes benign zygote jit swapped pages`() {
        val snapshot = MemoryNativeSnapshot(
            available = true,
            swappedExec = true,
            findings = listOf(
                MemoryNativeFinding(
                    section = "MAPS",
                    category = "SMAPS",
                    label = "Swapped executable pages",
                    severity = "MEDIUM",
                    detail = "[anon:dalvik-zygote-jit-code-cache] has 16 kB swapped executable pages",
                ),
            ),
        )

        val sanitized = repository.sanitizeSnapshot(snapshot)
        val mapsMethod = repository.buildMethods(sanitized).first { it.label == "maps + smaps" }

        assertFalse(sanitized.swappedExec)
        assertTrue(sanitized.findings.isEmpty())
        assertEquals("Clean", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.CLEAN, mapsMethod.outcome)
    }

    @Test
    fun `keeps swapped executable finding for non ART mapping`() {
        val snapshot = MemoryNativeSnapshot(
            available = true,
            swappedExec = true,
            findings = listOf(
                MemoryNativeFinding(
                    section = "MAPS",
                    category = "SMAPS",
                    label = "Swapped executable pages",
                    severity = "MEDIUM",
                    detail = "/system/lib64/libc.so has 4 kB swapped executable pages",
                ),
            ),
        )

        val sanitized = repository.sanitizeSnapshot(snapshot)
        val mapsMethod = repository.buildMethods(sanitized).first { it.label == "maps + smaps" }

        assertTrue(sanitized.swappedExec)
        assertEquals(1, sanitized.findings.size)
        assertEquals("Review", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.REVIEW, mapsMethod.outcome)
    }

    @Test
    fun `sanitizes ashmem zygote jit swapped pages variant`() {
        val finding = MemoryNativeFinding(
            section = "MAPS",
            category = "SMAPS",
            label = "Swapped executable pages",
            severity = "MEDIUM",
            detail = "/dev/ashmem/dalvik-zygote-jit-code-cache has 8 kB swapped executable pages",
        )

        assertTrue(repository.isBenignArtCodeCacheSwapFinding(finding))
    }

    @Test
    fun `sanitizes plain dalvik zygote jit token variant`() {
        val finding = MemoryNativeFinding(
            section = "MAPS",
            category = "SMAPS",
            label = "Swapped executable pages",
            severity = "MEDIUM",
            detail = "dalvik-zygote-jit-code-cache has 4 kB swapped executable pages",
        )

        assertTrue(repository.isBenignArtCodeCacheSwapFinding(finding))
    }

    @Test
    fun `sanitizes anon shmem dalvik jit token variant`() {
        val finding = MemoryNativeFinding(
            section = "MAPS",
            category = "SMAPS",
            label = "Swapped executable pages",
            severity = "MEDIUM",
            detail = "[anon_shmem:dalvik-zygote-jit-code-cache] has 16 kB swapped executable pages",
        )

        assertTrue(repository.isBenignArtCodeCacheSwapFinding(finding))
    }

    @Test
    fun `copied system code that matches its file leaves the row clean`() {
        val mapsMethod = repository.buildMethods(
            MemoryNativeSnapshot(available = true, systemAnonymousExec = true),
        ).first { it.label == "maps + smaps" }

        assertEquals("Clean", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.CLEAN, mapsMethod.outcome)
    }

    @Test
    fun `copied system code that could not be compared is review`() {
        val mapsMethod = repository.buildMethods(
            MemoryNativeSnapshot(available = true, systemAnonymousExec = true, systemCopyUnverified = true),
        ).first { it.label == "maps + smaps" }

        assertEquals("Review", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.REVIEW, mapsMethod.outcome)
    }

    @Test
    fun `copied system code that differs from its file is an anomaly`() {
        val mapsMethod = repository.buildMethods(
            MemoryNativeSnapshot(
                available = true,
                systemAnonymousExec = true,
                systemCopyModified = true,
                systemCopyUnverified = true,
            ),
        ).first { it.label == "maps + smaps" }

        assertEquals("Anomaly", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.DETECTED, mapsMethod.outcome)
    }

    @Test
    fun `anonymous executable mappings stay an anomaly`() {
        val mapsMethod = repository.buildMethods(
            MemoryNativeSnapshot(available = true, anonymousExec = true, systemAnonymousExec = true),
        ).first { it.label == "maps + smaps" }

        assertEquals("Anomaly", mapsMethod.summary)
        assertEquals(MemoryMethodOutcome.DETECTED, mapsMethod.outcome)
    }

    @Test
    fun `sanitizing keeps anonymous pages on the WebView provider's mapping`() {
        val snapshot = MemoryNativeSnapshot(
            available = true,
            systemAnonymousExec = true,
            findings = listOf(
                MemoryNativeFinding(
                    section = "MAPS",
                    category = "SMAPS",
                    label = "Anonymous executable pages on system mapping",
                    severity = "MEDIUM",
                    detail = "/product/app/webview/webview.apk reports 4 kB anonymous executable pages",
                ),
            ),
        )

        assertEquals(snapshot, repository.sanitizeSnapshot(snapshot))
    }
}
