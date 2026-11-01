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

import com.eltavine.duckdetector.features.mount.domain.MountFinding
import com.eltavine.duckdetector.features.mount.domain.MountFindingGroup
import com.eltavine.duckdetector.features.mount.domain.MountFindingOrigin
import com.eltavine.duckdetector.features.mount.domain.MountFindingSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MountPreloadFindingsTest {

    @Test
    fun `a startup mount id gap alone keeps its startup origin`() {
        val merged = mergePreloadFindings(emptyList(), listOf(startupMountIdGap))

        assertEquals(listOf(MountFindingSeverity.INFO), merged.map { it.severity })
        assertEquals(listOf(MountFindingOrigin.STARTUP_PRELOAD), merged.map { it.origin })
    }

    @Test
    fun `a startup mount id gap merged with a runtime one is seen by both captures`() {
        val merged = mergePreloadFindings(listOf(runtimeMountIdGap), listOf(startupMountIdGap))

        assertEquals(listOf(MountFindingSeverity.INFO), merged.map { it.severity })
        assertEquals(listOf(MountFindingOrigin.STARTUP_AND_RUNTIME), merged.map { it.origin })
    }

    @Test
    fun `runtime mount id gaps collapsed without a startup capture stay runtime`() {
        val merged = mergePreloadFindings(listOf(runtimeMountIdGap, runtimeMountIdGap.copy(value = "2")), emptyList())

        assertEquals(listOf(MountFindingSeverity.INFO), merged.map { it.severity })
        assertEquals(listOf(MountFindingOrigin.RUNTIME), merged.map { it.origin })
    }

    @Test
    fun `legacy and current runtime labels collapse without upgrading repeated observations`() {
        val merged = mergePreloadFindings(
            listOf(runtimeMountIdGap, runtimeMountIdGap.copy(label = MOUNT_ID_OBSERVATION_LABEL)),
            listOf(startupMountIdGap),
        )

        assertEquals(1, merged.size)
        assertEquals(MountFindingSeverity.INFO, merged.single().severity)
        assertEquals(MOUNT_ID_OBSERVATION_LABEL, merged.single().label)
        assertTrue(merged.single().detail.orEmpty().contains("do not establish hidden mounts"))
    }

    private val startupMountIdGap = MountFinding(
        id = "early_preload_mount_id_loophole",
        label = "Mount ID loophole",
        value = "Startup preload",
        group = MountFindingGroup.CONSISTENCY,
        severity = MountFindingSeverity.DANGER,
        detail = "Source=startup preload",
        origin = MountFindingOrigin.STARTUP_PRELOAD,
    )

    private val runtimeMountIdGap = MountFinding(
        id = "mount_id_loophole",
        label = "Mount ID loophole",
        value = "1",
        group = MountFindingGroup.CONSISTENCY,
        severity = MountFindingSeverity.DANGER,
        detail = "Missing mount ID 42",
    )
}
