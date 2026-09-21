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

package com.eltavine.duckdetector.features.zygisk.data.native

import com.eltavine.duckdetector.core.native.DuckDetectorNativeLibrary
import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

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
        return snapshot.copy(traces = traces)
    }

    private fun ZygiskNativeSnapshot.applyEntry(
        key: String,
        value: String,
    ): ZygiskNativeSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "HEAP_AVAILABLE" -> copy(heapAvailable = value.asBool())
            "SECCOMP_SUPPORTED" -> copy(seccompSupported = value.asBool())
            "TRACER_PID" -> copy(tracerPid = value.toIntOrNull() ?: tracerPid)
            "STRONG_HITS" -> copy(strongHitCount = value.toIntOrNull() ?: strongHitCount)
            "HEURISTIC_HITS" -> copy(heuristicHitCount = value.toIntOrNull() ?: heuristicHitCount)
            "SOLIST_HITS" -> copy(solistHitCount = value.toIntOrNull() ?: solistHitCount)
            "VMAP_HITS" -> copy(vmapHitCount = value.toIntOrNull() ?: vmapHitCount)
            "ATEXIT_HITS" -> copy(atexitHitCount = value.toIntOrNull() ?: atexitHitCount)
            "SMAPS_HITS" -> copy(smapsHitCount = value.toIntOrNull() ?: smapsHitCount)
            "NAMESPACE_HITS" -> copy(namespaceHitCount = value.toIntOrNull() ?: namespaceHitCount)
            "LINKER_HOOK_HITS" -> copy(
                linkerHookHitCount = value.toIntOrNull() ?: linkerHookHitCount
            )

            "STACK_LEAK_HITS" -> copy(stackLeakHitCount = value.toIntOrNull() ?: stackLeakHitCount)
            "SECCOMP_HITS" -> copy(seccompHitCount = value.toIntOrNull() ?: seccompHitCount)
            "HEAP_HITS" -> copy(heapHitCount = value.toIntOrNull() ?: heapHitCount)
            "THREAD_HITS" -> copy(threadHitCount = value.toIntOrNull() ?: threadHitCount)
            "FD_HITS" -> copy(fdHitCount = value.toIntOrNull() ?: fdHitCount)
            else -> this
        }
    }

    private fun String.asBool(): Boolean = NativePayloadCodec.decodeFlag(this)

    private fun String.decodeValue(): String = NativePayloadCodec.decodeValue(this)

    private external fun nativeCollectSnapshot(): String
}
