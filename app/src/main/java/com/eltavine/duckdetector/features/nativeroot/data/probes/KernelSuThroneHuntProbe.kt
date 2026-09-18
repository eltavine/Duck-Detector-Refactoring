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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.data.native.ThroneHuntWatchNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup

data class KernelSuThroneHuntProbeResult(
    val available: Boolean,
    val watchInstalled: Boolean,
    val watchDenied: Boolean,
    val packageDirectory: String,
    val directoryOpenCount: Int,
    val directoryAccessCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val hitCount: Int
        get() = directoryOpenCount + directoryAccessCount
}

// KernelSU's pkg_observer watches /data/system for a "packages.list" FS_CREATE|FS_MOVE and then
// runs track_throne -> search_manager("/data/app", 2). search_manager does filp_open() plus
// iterate_dir() on every package directory inode, so an inotify watch placed on our own package
// directory observes a directory IN_OPEN/IN_ACCESS that no ordinary app activity produces.
//
// The watch is installed during app_zygote preload and the packages.list rewrite is driven by
// KernelSuThroneHuntRound from the main process. Reading the stream consumes it, so this probe only
// turns the counts the round already collected into findings.
class KernelSuThroneHuntProbe {

    fun run(round: KernelSuThroneHuntRoundResult): KernelSuThroneHuntProbeResult {
        if (!round.available) {
            return KernelSuThroneHuntProbeResult(
                available = false,
                watchInstalled = false,
                watchDenied = round.watchDenied,
                packageDirectory = round.packageDirectory,
                directoryOpenCount = 0,
                directoryAccessCount = 0,
                findings = emptyList(),
                detail = round.detail,
            )
        }

        val detail = buildString {
            append("packageDir=")
            append(round.packageDirectory)
            append("\ndirectoryOpen=")
            append(round.directoryOpenCount)
            append("\ndirectoryAccess=")
            append(round.directoryAccessCount)
            append('\n')
            append(round.detail)
        }

        return KernelSuThroneHuntProbeResult(
            available = true,
            watchInstalled = true,
            watchDenied = round.watchDenied,
            packageDirectory = round.packageDirectory,
            directoryOpenCount = round.directoryOpenCount,
            directoryAccessCount = round.directoryAccessCount,
            findings = buildFindings(
                round.directoryOpenCount,
                round.directoryAccessCount,
                detail,
            ),
            detail = detail,
        )
    }

    private fun buildFindings(
        openCount: Int,
        accessCount: Int,
        detail: String,
    ): List<NativeRootFinding> {
        // A clean round must not emit a finding, otherwise PACKAGE-group additions would be counted
        // as runtime hits by the Kotlin layer and turn "no traversal" into a false positive.
        if (openCount + accessCount == 0) {
            return emptyList()
        }
        return listOf(
            NativeRootFinding(
                id = "ksu_throne_hunt",
                label = "KernelSU throne hunt",
                value = "open=$openCount access=$accessCount",
                detail = detail,
                group = NativeRootGroup.PACKAGE,
                severity = NativeRootFindingSeverity.DANGER,
                detailMonospace = true,
            )
        )
    }
}
