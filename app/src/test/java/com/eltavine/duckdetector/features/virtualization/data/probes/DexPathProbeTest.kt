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

package com.eltavine.duckdetector.features.virtualization.data.probes

import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DexPathProbeTest {

    private val probe = DexPathProbe()

    @Test
    fun `host apk path hit maps to danger`() {
        val result = probe.evaluate(
            entries = listOf(
                "/data/app/com.vmos.pro/base.apk",
                "/data/app/com.eltavine.duckdetector/base.apk",
            ),
            sourceDir = "/data/app/com.eltavine.duckdetector/base.apk",
            splitSourceDirs = emptyList(),
            packageName = "com.eltavine.duckdetector",
        )

        assertTrue(
            result.signals.any {
                it.label == "Host dex path" &&
                        it.severity == VirtualizationSignalSeverity.DANGER
            },
        )
        assertTrue(result.hostPathHit)
    }

    @Test
    fun `prepended third party dex maps to danger`() {
        val result = probe.evaluate(
            entries = listOf(
                "/data/local/tmp/injected.jar",
                "/data/app/com.eltavine.duckdetector/base.apk",
            ),
            sourceDir = "/data/app/com.eltavine.duckdetector/base.apk",
            splitSourceDirs = emptyList(),
            packageName = "com.eltavine.duckdetector",
        )

        assertTrue(
            result.signals.any {
                it.label == "Prepended third-party dex" &&
                        it.severity == VirtualizationSignalSeverity.DANGER
            },
        )
    }

    @Test
    fun `split source mismatch only maps to warning`() {
        val result = probe.evaluate(
            entries = listOf("/data/app/com.eltavine.duckdetector/base.apk"),
            sourceDir = "/data/app/com.eltavine.duckdetector/base.apk",
            splitSourceDirs = listOf("/data/app/com.eltavine.duckdetector/split_config.arm64_v8a.apk"),
            packageName = "com.eltavine.duckdetector",
        )

        assertEquals(1, result.hitCount)
        assertTrue(
            result.signals.any {
                it.label == "Classpath/source mismatch" &&
                        it.severity == VirtualizationSignalSeverity.WARNING
            },
        )
    }

    @Test
    fun `system and apex paths are filtered`() {
        val result = probe.evaluate(
            entries = listOf(
                "/system/framework/framework.jar",
                "/apex/com.android.art/javalib/core-oj.jar",
                "/data/app/com.eltavine.duckdetector/base.apk",
            ),
            sourceDir = "/data/app/com.eltavine.duckdetector/base.apk",
            splitSourceDirs = emptyList(),
            packageName = "com.eltavine.duckdetector",
        )

        assertEquals(1, result.entryCount)
        assertTrue(result.signals.isEmpty())
    }

    @Test
    fun `own overlay dex path is ignored`() {
        val result = probe.evaluate(
            entries = listOf(
                "/data/data/com.eltavine.duckdetector/code_cache/.overlay/base.apk/classes10.dex",
                "/data/app/com.eltavine.duckdetector/base.apk",
            ),
            sourceDir = "/data/app/com.eltavine.duckdetector/base.apk",
            splitSourceDirs = emptyList(),
            packageName = "com.eltavine.duckdetector",
        )

        assertEquals(1, result.entryCount)
        assertTrue(result.signals.isEmpty())
        assertTrue(!result.hostPathHit)
    }
}
