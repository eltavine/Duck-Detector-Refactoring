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

package com.eltavine.duckdetector.features.playintegrityfix.data.native

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

class PlayIntegrityFixNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    fun collectSnapshot(
        propertyNames: Collection<String>,
    ): PlayIntegrityFixNativeSnapshot = collector.collect(
        readPayload = {
            nativeCollectSnapshot(propertyNames.distinct().sorted().toTypedArray())
        },
        parse = ::parse,
        unavailable = { status -> PlayIntegrityFixNativeSnapshot(collection = status) },
    )

    internal fun parse(raw: String): PlayIntegrityFixNativeSnapshot {
        if (raw.isBlank()) {
            return PlayIntegrityFixNativeSnapshot()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        var available = false
        val properties = linkedMapOf<String, String>()
        val traces = mutableListOf<PlayIntegrityFixNativeTrace>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && it.contains('=') }
            .forEach { line ->
                val key = line.substringBefore('=')
                val value = line.substringAfter('=')
                when (key) {
                    "AVAILABLE" -> available = NativePayloadCodec.decodeFlag(value)

                    "PROP" -> {
                        val parts = value.split('|', limit = 2)
                        if (parts.size == 2) {
                            properties[parts[0]] = parts[1].decodeValue()
                        }
                    }

                    "TRACE" -> {
                        val parts = value.split('\t', limit = 3)
                        if (parts.size == 3) {
                            traces += PlayIntegrityFixNativeTrace(
                                severity = parts[0],
                                label = parts[1],
                                detail = parts[2].decodeValue(),
                            )
                        }
                    }
                }
            }

        return PlayIntegrityFixNativeSnapshot(
            available = available,
            nativeProperties = properties,
            runtimeTraces = traces,
        )
    }

    private fun String.decodeValue(): String = NativePayloadCodec.decodeValue(this)

    private external fun nativeCollectSnapshot(propertyNames: Array<String>): String
}
