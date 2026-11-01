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

import com.eltavine.duckdetector.features.mount.domain.MountMethodOutcome
import com.eltavine.duckdetector.features.mount.domain.MountStage
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextNamespaceAssessment
import com.eltavine.duckdetector.features.mount.domain.MountZygoteNextExposure
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountZygoteNextRepositoryTest {

    @Test
    fun `isolated root marker becomes one direct mount danger signal`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(rootMarker()),
        ).scan()

        assertEquals(MountStage.READY, report.stage)
        assertTrue(report.zygoteNext.leakDetected)
        assertEquals(MountZygoteNextExposure.ROOT_MOUNT_EXPOSURE, report.zygoteNext.exposure)
        assertEquals(
            "ROOT_MOUNT_EXPOSURE",
            report.dangerFindings.single { it.id == "zygote_next_root_mount_exposure" }.value,
        )
        assertEquals(1, report.dangerSignalCount)
        assertEquals(
            MountMethodOutcome.DANGER,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `shared contrast without root marker remains clean`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult(),
        ).scan()

        assertTrue(report.zygoteNext.contrastObserved)
        assertEquals(
            MountZygoteNextNamespaceAssessment.LIKELY_INIT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(0, report.dangerSignalCount)
        assertEquals(0, report.warningSignalCount)
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `missing mount id ordering is support instead of clean`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(rootMountId = 0L),
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
    fun `higher native mount id high-water does not override older root anchors`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(maximumMountId = 421L),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.LIKELY_INIT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.CLEAN,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `short mount tables are unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(mountCount = 7),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `shared native root without slave classic root is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:1"),
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
    fun `shared and slave propagation is inconsistent`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(rootPropagation = "shared:2 master:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.INCONSISTENT,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `fewer than three common anchors is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                mainProcess = base.mainProcess.copy(
                    mountIdsByPoint = mapOf("/" to 240, "/dev" to 241),
                ),
                isolatedProcess = base.isolatedProcess.copy(
                    mountIdsByPoint = mapOf("/" to 24, "/dev" to 25),
                ),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }

    @Test
    fun `shared and master on isolated root is inconsistent`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(
                    rootPropagation = "shared:1 master:2",
                ),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.INCONSISTENT,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `private isolated root is a namespace observation`() = runBlocking {
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = readyResult().copy(
                isolatedProcess = readyResult().isolatedProcess.copy(rootPropagation = "master:1"),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.PRIVATE_ANOMALY,
            report.zygoteNext.namespaceAssessment,
        )
        assertEquals(0, report.warningSignalCount)
        assertEquals(
            MountMethodOutcome.SUPPORT,
            report.methods.single { it.label == "Zygote next mount view" }.outcome,
        )
    }

    @Test
    fun `invalid isolated uid is unverified`() = runBlocking {
        val base = readyResult()
        val report = repository(
            nativeSnapshot = cleanSnapshot(),
            zygoteNextResult = base.copy(
                isolatedProcess = base.isolatedProcess.copy(uid = 10000),
            ),
        ).scan()

        assertEquals(
            MountZygoteNextNamespaceAssessment.UNVERIFIED,
            report.zygoteNext.namespaceAssessment,
        )
    }
}
