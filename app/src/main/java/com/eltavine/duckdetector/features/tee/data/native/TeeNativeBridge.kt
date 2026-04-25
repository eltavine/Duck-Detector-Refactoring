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

package com.eltavine.duckdetector.features.tee.data.native

class TeeNativeBridge {

    fun collectSnapshot(leafDer: ByteArray?): NativeTeeSnapshot {
        return runCatching {
            decodeSnapshot(
                environmentRaw = nativeCollectEnvironment(),
                trickyRaw = nativeInspectTrickyStore(),
                derRaw = leafDer?.let(::nativeInspectLeafDer).orEmpty(),
            )
        }.getOrDefault(NativeTeeSnapshot())
    }

    internal fun decodeSnapshot(
        environmentRaw: String,
        trickyRaw: String,
        derRaw: String,
    ): NativeTeeSnapshot {
        val env = parseKeyValueLines(environmentRaw)
        val tricky = parseKeyValueLines(trickyRaw)
        val der = parseKeyValueLines(derRaw)
        return NativeTeeSnapshot(
            tracingDetected = env["TRACING"] == "1",
            suspiciousMappings = env.filterKeys { it == "MAPPING" || it.startsWith("MAPPING_") }.values.toList(),
            trickyStoreDetected = tricky["DETECTED"] == "1",
            gotHookDetected = tricky["GOT_HOOK"] == "1",
            syscallMismatchDetected = tricky["SYSCALL_MISMATCH"] == "1",
            inlineHookDetected = tricky["INLINE_HOOK"] == "1",
            honeypotDetected = tricky["HONEYPOT"] == "1",
            trickyStoreTimerSource = tricky["TIMER_SOURCE"] ?: "unknown",
            trickyStoreTimerFallbackReason = tricky["TIMER_FALLBACK"]?.takeIf { it.isNotBlank() },
            trickyStoreAffinityStatus = tricky["AFFINITY"] ?: "not_requested",
            trickyStoreTimingRunCount = tricky["RUNS"]?.toIntOrNull(),
            trickyStoreTimingSuspiciousRunCount = tricky["SUSPICIOUS_RUNS"]?.toIntOrNull(),
            trickyStoreTimingMedianGapNs = tricky["MEDIAN_GAP_NS"]?.toLongOrNull(),
            trickyStoreTimingGapMadNs = tricky["GAP_MAD_NS"]?.toLongOrNull(),
            trickyStoreTimingMedianNoiseFloorNs = tricky["MEDIAN_NOISE_NS"]?.toLongOrNull(),
            trickyStoreTimingMedianRatioPercent = tricky["MEDIAN_RATIO_PERCENT"]?.toIntOrNull(),
            trickyStoreMethods = tricky.filterKeys { it == "METHOD" || it.startsWith("METHOD_") }.values.toList(),
            trickyStoreDetails = tricky["DETAILS"] ?: "Native trickystore probe unavailable",
            leafDerPrimaryDetected = der["PRIMARY"] == "1",
            leafDerSecondaryDetected = der["SECONDARY"] == "1",
            leafDerFindings = der.filterKeys { it == "FINDING" || it.startsWith("FINDING_") }.values.toList(),
            pageSize = env["PAGE_SIZE"]?.toIntOrNull(),
            timingSummary = env["TIMING"],
        )
    }

    private fun parseKeyValueLines(raw: String): Map<String, String> {
        val indexedKeys = hashMapOf<String, Int>()
        return buildMap {
            raw.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && it.contains('=') }
                .forEach { line ->
                    val key = line.substringBefore('=')
                    val value = line.substringAfter('=')
                    val index = indexedKeys.getOrDefault(key, 0)
                    indexedKeys[key] = index + 1
                    if (index == 0) {
                        put(key, value)
                    } else {
                        put("${key}_$index", value)
                    }
                }
        }
    }

    private external fun nativeCollectEnvironment(): String

    private external fun nativeInspectTrickyStore(): String

    private external fun nativeInspectLeafDer(leafDer: ByteArray): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
