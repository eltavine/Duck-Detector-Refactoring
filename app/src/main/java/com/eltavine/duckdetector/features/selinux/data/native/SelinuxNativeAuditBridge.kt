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

package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

open class SelinuxNativeAuditBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    open fun collectSnapshot(): SelinuxNativeAuditSnapshot = collector.collect(
        readPayload = ::nativeCollectAuditSnapshot,
        parse = ::parse,
        unavailable = { status ->
            // Previously an unloadable library produced a fixed reason while a probe that threw
            // produced no reason at all, which read as a successful scan that found no denials.
            SelinuxNativeAuditSnapshot(
                failureReason = status.explain("Native SELinux audit snapshot was unavailable"),
                collection = status,
            )
        },
    )

    internal fun parse(raw: String): SelinuxNativeAuditSnapshot {
        if (raw.isBlank()) {
            return SelinuxNativeAuditSnapshot()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        var snapshot = SelinuxNativeAuditSnapshot()
        val callbackLines = mutableListOf<String>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("LINE=") -> callbackLines += line.removePrefix("LINE=")
                        .decodeValue()

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = snapshot.applyEntry(key, value)
                    }
                }
            }

        return snapshot.copy(callbackLines = callbackLines)
    }

    private fun SelinuxNativeAuditSnapshot.applyEntry(
        key: String,
        value: String,
    ): SelinuxNativeAuditSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "CALLBACK_INSTALLED" -> copy(callbackInstalled = value.asBool())
            "PROBE_RAN" -> copy(probeRan = value.asBool())
            "DENIAL_OBSERVED" -> copy(denialObserved = value.asBool())
            "ALLOW_OBSERVED" -> copy(allowObserved = value.asBool())
            "PROBE_MARKER" -> copy(probeMarker = value.decodeValue())
            "FAILURE_REASON" -> copy(failureReason = value.decodeValue())
            else -> this
        }
    }

    private fun String.asBool(): Boolean = NativePayloadCodec.decodeFlag(this)

    private fun String.decodeValue(): String = NativePayloadCodec.decodeValue(this)

    private external fun nativeCollectAuditSnapshot(): String
}
