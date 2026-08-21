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

package com.eltavine.duckdetector.features.mount.data.zygotenext

enum class ZygoteNextProbeState {
    UNSUPPORTED,
    UNAVAILABLE,
    READY,
}

data class ZygoteNextMountMarker(
    val labels: List<String>,
    val mountPoint: String,
    val mountRoot: String,
    val fileSystemType: String,
    val source: String,
    val rawLine: String,
) {
    val dangerous: Boolean
        get() = labels.any { it != DEBUG_RAMDISK_LABEL }

    companion object {
        const val DEBUG_RAMDISK_LABEL = "debug_ramdisk"
    }
}

data class ZygoteNextProcessSnapshot(
    val available: Boolean = false,
    val pid: Int = 0,
    val parentPid: Int = 0,
    val uid: Int = 0,
    val mountNamespaceInode: Long = 0L,
    val rootPropagation: String = "",
    val rootMountId: Long = 0L,
    val minimumMountId: Long = 0L,
    val maximumMountId: Long = 0L,
    val mountCount: Int = 0,
    val markers: List<ZygoteNextMountMarker> = emptyList(),
    val errorDetail: String = "",
)

data class ZygoteNextProbeResult(
    val state: ZygoteNextProbeState,
    val sdkInt: Int,
    val mainProcess: ZygoteNextProcessSnapshot = ZygoteNextProcessSnapshot(),
    val isolatedProcess: ZygoteNextProcessSnapshot = ZygoteNextProcessSnapshot(),
    val errorDetail: String = "",
) {
    companion object {
        fun unsupported(sdkInt: Int): ZygoteNextProbeResult {
            return ZygoteNextProbeResult(
                state = ZygoteNextProbeState.UNSUPPORTED,
                sdkInt = sdkInt,
                errorDetail = "Zygote next native services require Android 17 (API 37).",
            )
        }

        fun unavailable(
            sdkInt: Int,
            detail: String,
            mainProcess: ZygoteNextProcessSnapshot = ZygoteNextProcessSnapshot(),
        ): ZygoteNextProbeResult {
            return ZygoteNextProbeResult(
                state = ZygoteNextProbeState.UNAVAILABLE,
                sdkInt = sdkInt,
                mainProcess = mainProcess,
                errorDetail = detail,
            )
        }
    }
}
