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

package com.eltavine.duckdetector.features.mount.presentation

import com.eltavine.duckdetector.features.mount.domain.MountReport
import com.eltavine.duckdetector.features.mount.domain.toDetectorStatus
import com.eltavine.duckdetector.features.mount.presentation.model.MountCardModel

class MountCardModelMapper {
    fun map(
        report: MountReport,
    ): MountCardModel {
        return MountCardModel(
            title = "Mount",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            procMountViewRows = listOf(
                procMountViewRow(report),
                zygoteNextMountViewRow(report),
            ),
            artifactRows = buildRows(
                report.stage,
                report.artifactRows,
                listOf("Magisk mounts", "Zygisk/Riru", "/data/adb", "Debug ramdisk")
            ),
            runtimeRows = buildRows(
                report.stage,
                report.runtimeRows,
                listOf("System RW", "Overlay mounts", "Loop devices", "dm-verity bypass")
            ),
            filesystemRows = buildRows(
                report.stage,
                report.filesystemRows,
                listOf("Overlayfs support", "System filesystem type", "Tmpfs anomaly")
            ),
            consistencyRows = buildRows(
                report.stage,
                report.consistencyRows,
                listOf(
                    "Namespace access",
                    "Shell tmp view",
                    "Mount consistency",
                    "Mount ID discontinuity",
                    "Anonymous device minors",
                    "Bind mount root"
                )
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }
}
