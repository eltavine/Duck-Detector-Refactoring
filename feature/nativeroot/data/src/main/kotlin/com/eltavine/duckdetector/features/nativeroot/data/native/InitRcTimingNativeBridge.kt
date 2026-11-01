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

package com.eltavine.duckdetector.features.nativeroot.data.native

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingRound

class InitRcTimingNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    fun collect(directory: String): InitRcTimingObservation = collector.collect(
        readPayload = { nativeCollect(directory) },
        parse = ::parse,
        unavailable = { status ->
            InitRcTimingObservation(
                collection = InitRcTimingCollection.NATIVE_FAILED,
                failureDetail = "${status.outcome}: ${status.detail}",
            )
        },
    )

    internal fun parse(raw: String): InitRcTimingObservation {
        require(raw.length <= 16_384) { "Oversized init.rc timing payload" }
        val fields = mutableMapOf<String, String>()
        val rounds = mutableListOf<InitRcTimingRound>()
        raw.lineSequence().filter { it.isNotEmpty() }.forEach { line ->
            require('=' in line) { "Malformed init.rc timing field" }
            val key = line.substringBefore('=')
            val value = line.substringAfter('=')
            if (key == "ROUND") {
                require(rounds.size < 32) { "Too many init.rc timing rounds" }
                val parts = value.split('\t').map { NativePayloadCodec.decodeValue(it).toLong() }
                require(parts.size == 4 && parts.all { it in 1..1_000_000_000L })
                rounds += InitRcTimingRound(parts[0], parts[1], parts[2], parts[3])
            } else {
                require(fields.put(key, NativePayloadCodec.decodeValue(value)) == null) { "Duplicate timing field" }
            }
        }
        require(fields["VERSION"] == "1" && fields["ITERATIONS"] == "128")
        require(fields["COUNT"]?.toInt() == rounds.size)
        require(fields["CLEANUP"] in setOf("0", "1"))
        val stageCode = requireNotNull(fields["STAGE"]).toInt()
        val stage = requireNotNull(InitRcTimingCollection.entries.singleOrNull { it.wireCode == stageCode })
        require(stageCode in 0..9) { "Unknown native timing stage" }
        val cpu = requireNotNull(fields["CPU"]).toInt().also { require(it >= -1) }
        val error = requireNotNull(fields["ERROR"]).toInt().also { require(it >= 0) }
        val cleanupError = requireNotNull(fields["CLEANUP_ERROR"]).toInt().also { require(it >= 0) }
        val cleaned = fields["CLEANUP"] == "1"
        require(!cleaned || cleanupError == 0)
        val observation = InitRcTimingObservation(stage, rounds, 128, cpu, error, cleanupError, cleaned)
        if (stage == InitRcTimingCollection.COLLECTED) {
            require(observation.hasCompleteSample && error == 0 && cleaned && cleanupError == 0)
        }
        return observation
    }

    private external fun nativeCollect(directory: String): String
}
