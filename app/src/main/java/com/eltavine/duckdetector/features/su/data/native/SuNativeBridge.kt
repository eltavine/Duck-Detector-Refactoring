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

package com.eltavine.duckdetector.features.su.data.native

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

class SuNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    fun collectSnapshot(): SuNativeSnapshot = collector.collect(
        readPayload = ::nativeCollectSnapshot,
        parse = ::parse,
        unavailable = { status -> SuNativeSnapshot(collection = status) },
    )

    internal fun parse(raw: String): SuNativeSnapshot {
        if (raw.isBlank()) {
            return SuNativeSnapshot()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        val entries = raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .map { it.substringBefore('=') to it.substringAfter('=') }
            .toList()

        return SuNativeSnapshot(
            available = NativePayloadCodec.decodeFlag(entries.firstOrNull { it.first == "AVAILABLE" }?.second),
            selfContext = entries.firstOrNull { it.first == "SELF_CONTEXT" }?.second.orEmpty(),
            selfContextAbnormal = NativePayloadCodec.decodeFlag(
                entries.firstOrNull { it.first == "SELF_ABNORMAL" }?.second,
            ),
            suspiciousProcesses = entries.filter { it.first == "PROC" }.map { it.second },
            checkedProcesses = entries.firstOrNull { it.first == "PROC_CHECKED" }?.second?.toIntOrNull()
                ?: 0,
            deniedProcesses = entries.firstOrNull { it.first == "PROC_DENIED" }?.second?.toIntOrNull()
                ?: 0,
        )
    }

    private external fun nativeCollectSnapshot(): String
}
