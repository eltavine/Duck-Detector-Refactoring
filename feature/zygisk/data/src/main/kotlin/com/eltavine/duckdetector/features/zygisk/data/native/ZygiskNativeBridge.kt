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

package com.eltavine.duckdetector.features.zygisk.data.native

import com.eltavine.duckdetector.core.native.DuckDetectorNativeLibrary
import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskAtexitState

class ZygiskNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    private val nativeLoaded: Boolean
        get() = DuckDetectorNativeLibrary.isLoaded

    fun isNativeAvailable(): Boolean = nativeLoaded

    fun collectSnapshot(): ZygiskNativeSnapshot = collector.collect(
        readPayload = ::nativeCollectSnapshot,
        parse = ::parse,
        unavailable = { status -> ZygiskNativeSnapshot(collection = status) },
    )

    internal fun parse(raw: String): ZygiskNativeSnapshot {
        if (raw.isBlank()) {
            return ZygiskNativeSnapshot()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        var snapshot = ZygiskNativeSnapshot()
        val traces = mutableListOf<ZygiskNativeTrace>()
        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("TRACE=") -> {
                        val parts = line.removePrefix("TRACE=").split('\t', limit = 4)
                        if (parts.size == 4) {
                            traces += ZygiskNativeTrace(
                                group = parts[0],
                                severity = parts[1],
                                label = parts[2].decodeValue(),
                                detail = parts[3].decodeValue(),
                            )
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = snapshot.applyEntry(key, value)
                    }
                }
            }
        val table = snapshot.atexitTable
        if (table.state == ZygiskAtexitState.COLLECTED || table.state == ZygiskAtexitState.PARTIAL) {
            NativePayloadContract.requireKeys(raw,
                "ATEXIT_TABLE_ENTRIES", "ATEXIT_TABLE_NULLS", "ATEXIT_TABLE_GAPS",
                "ATEXIT_TABLE_CALLBACKS", "ATEXIT_TABLE_DETAIL",
            )
            require(table.state != ZygiskAtexitState.COLLECTED || table.entries > 0) {
                "Evaluated exit-handler coverage requires a nonempty bounded table."
            }
            require(table.nullEntries <= table.entries && table.anchoredGaps <= table.nullEntries / 3 &&
                table.anonymousCallbacks <= table.entries - table.nullEntries) {
                "Contradictory exit-handler counts in native payload."
            }
        }
        return snapshot.copy(traces = traces)
    }

    private fun ZygiskNativeSnapshot.applyEntry(
        key: String,
        value: String,
    ): ZygiskNativeSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "HEAP_AVAILABLE" -> copy(heapAvailable = value.asBool())
            "TRACER_PID" -> copy(tracerPid = value.toIntOrNull() ?: tracerPid)
            "STRONG_HITS" -> copy(strongHitCount = value.toIntOrNull() ?: strongHitCount)
            "HEURISTIC_HITS" -> copy(heuristicHitCount = value.toIntOrNull() ?: heuristicHitCount)
            "SOLIST_HITS" -> copy(solistHitCount = value.toIntOrNull() ?: solistHitCount)
            "VMAP_HITS" -> copy(vmapHitCount = value.toIntOrNull() ?: vmapHitCount)
            "ATEXIT_HITS" -> copy(atexitHitCount = value.toIntOrNull() ?: atexitHitCount)
            "ATEXIT_TABLE_STATE" -> copy(atexitTable = atexitTable.copy(
                state = when (value) {
                    "COLLECTED" -> ZygiskAtexitState.COLLECTED
                    "UNSUPPORTED" -> ZygiskAtexitState.UNSUPPORTED
                    "UNAVAILABLE" -> ZygiskAtexitState.UNAVAILABLE
                    "PERMISSION_DENIED" -> ZygiskAtexitState.PERMISSION_DENIED
                    "BUSY" -> ZygiskAtexitState.BUSY
                    "INVALID" -> ZygiskAtexitState.INVALID
                    "PARTIAL" -> ZygiskAtexitState.PARTIAL
                    else -> ZygiskAtexitState.NOT_COLLECTED
                },
            ))
            "ATEXIT_TABLE_DUMPABLE" -> copy(atexitTable = atexitTable.copy(
                dumpable = value.toIntOrNull()?.takeIf { it in 0..2 } ?: -1,
            ))
            "ATEXIT_TABLE_ENTRIES" -> copy(atexitTable = atexitTable.copy(entries = value.toCount()))
            "ATEXIT_TABLE_NULLS" -> copy(atexitTable = atexitTable.copy(nullEntries = value.toCount()))
            "ATEXIT_TABLE_GAPS" -> copy(atexitTable = atexitTable.copy(anchoredGaps = value.toCount()))
            "ATEXIT_TABLE_CALLBACKS" -> copy(atexitTable = atexitTable.copy(anonymousCallbacks = value.toCount()))
            "ATEXIT_TABLE_DETAIL" -> copy(atexitTable = atexitTable.copy(detail = value.decodeValue()))
            "SMAPS_HITS" -> copy(smapsHitCount = value.toIntOrNull() ?: smapsHitCount)
            "NAMESPACE_HITS" -> copy(namespaceHitCount = value.toIntOrNull() ?: namespaceHitCount)
            "LINKER_HOOK_HITS" -> copy(
                linkerHookHitCount = value.toIntOrNull() ?: linkerHookHitCount
            )

            "HEAP_HITS" -> copy(heapHitCount = value.toIntOrNull() ?: heapHitCount)
            "THREAD_HITS" -> copy(threadHitCount = value.toIntOrNull() ?: threadHitCount)
            "FD_HITS" -> copy(fdHitCount = value.toIntOrNull() ?: fdHitCount)
            else -> this
        }
    }

    private fun String.asBool(): Boolean = NativePayloadCodec.decodeFlag(this)

    private fun String.toCount(): Int = requireNotNull(toIntOrNull()?.takeIf { it >= 0 }) {
        "Invalid exit-handler count in native payload."
    }

    private fun String.decodeValue(): String = NativePayloadCodec.decodeValue(this)

    private external fun nativeCollectSnapshot(): String
}
