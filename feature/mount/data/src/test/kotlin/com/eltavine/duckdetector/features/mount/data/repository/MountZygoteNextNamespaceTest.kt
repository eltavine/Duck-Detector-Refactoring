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

package com.eltavine.duckdetector.features.mount.data.repository

import com.eltavine.duckdetector.features.mount.data.native.MountNativeSnapshot
import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountZygoteNextNamespaceTest {

    @Test
    fun `reused anchor ids do not contradict namespace ancestry`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(
                    mountIdsByPoint = mapOf("/" to 250, "/dev" to 251, "/proc" to 252),
                ),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(MountMethodOutcome.SUPPORT, report.methods.single {
            it.label == "Zygote next mount view"
        }.outcome)
    }

    @Test
    fun `matching namespace identities are unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(mountNamespaceInode = 10L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `root marker remains dangerous when namespace coverage is unverified`() = runBlocking {
        val base = readyResult(rootMarker())
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `root marker in main process alone remains clean`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(markers = listOf(rootMarker())),
            ),
        ).scan()

        assertEquals(0, report.dangerSignalCount)
        assertTrue(report.zygoteNext.dangerousMarkers.isEmpty())
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `zygote next evidence survives local native mount failure`() = runBlocking {
        val report = repository(
            nativeSnapshot = MountNativeSnapshot(available = false),
            zygoteNextResult = readyResult(rootMarker()),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `zygote next evidence survives thrown local native mount failure`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(rootMarker()),
            nativeFailure = IllegalStateException("native bridge crashed"),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(1, report.dangerSignalCount)
        assertEquals("native bridge crashed", report.errorMessage)
    }

    @Test
    fun `private namespace observation survives unavailable native snapshot`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = MountNativeSnapshot(available = false),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertEquals(0, report.warningSignalCount)
        assertEquals(
            "Coverage unverified",
            report.findings.single { it.id == "zygote_next_namespace_anomaly" }.value,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `namespace difference observation survives thrown native failure`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:2 master:1"),
            ),
            nativeFailure = IllegalStateException("native bridge crashed"),
        ).scan()

        assertEquals(MountStage.FAILED, report.stage)
        assertEquals(0, report.warningSignalCount)
        assertEquals(
            "Coverage unverified",
            report.findings.single { it.id == "zygote_next_namespace_anomaly" }.value,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }
}
