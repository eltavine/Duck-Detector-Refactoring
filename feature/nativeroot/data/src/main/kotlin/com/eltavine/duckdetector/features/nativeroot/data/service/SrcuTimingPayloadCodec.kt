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

package com.eltavine.duckdetector.features.nativeroot.data.service

import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.features.nativeroot.data.native.SrcuTimingNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.ROUND_COUNT
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingRound
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingWindow

internal object SrcuTimingPayloadCodec {
    // Rejects a malformed or oversized reply; a real saturated run stays well below it. The reply can
    // still exceed the one-way Binder budget, so the carrier falls back to a bounded failure.
    const val MAX_LENGTH = 400_000
    private fun field(key: String, value: String) = "$key=${NativePayloadCodec.encodeValue(value)}\n"
    fun encode(observation: SrcuTimingObservation): String = buildString {
        append(field("VERSION", "1"))
        append(field("COLLECTION", observation.collection.name))
        append(field("KERNEL", observation.kernelRelease))
        append(field("DETAIL", observation.failureDetail.take(2048)))
        append(field("CLEANUP", if (observation.cleanupCompleted) "1" else "0"))
        observation.failedWindow?.let { append(field("FAILED_WINDOW", encodeWindow(it))) }
        observation.rounds.forEach { round ->
            append("ROUND=")
            append(listOf(round.idle, round.stimulated, round.sequential)
                .joinToString("\t") { NativePayloadCodec.encodeValue(encodeWindow(it)) })
            append('\n')
        }
    }.also { require(it.length <= MAX_LENGTH) }

    private fun encodeWindow(window: SrcuTimingWindow): String = buildString {
        append(field("VERSION", "1"))
        append(field("BEGIN", window.beginNanos.toString()))
        append(field("END", window.endNanos.toString()))
        append(field("SATURATED", if (window.saturated) "1" else "0"))
        append(field("COUNT", window.samples.size.toString()))
        window.samples.forEach { sample ->
            append("SAMPLE=")
            append(listOf(sample.beginNanos, sample.endNanos, sample.stage.ordinal, sample.errorNumber)
                .joinToString("\t") { NativePayloadCodec.encodeValue(it.toString()) })
            append('\n')
        }
    }

    fun decode(raw: String): SrcuTimingObservation {
        require(raw.length <= MAX_LENGTH)
        val fields = mutableMapOf<String, String>()
        val rounds = mutableListOf<SrcuTimingRound>()
        val parser = SrcuTimingNativeBridge()
        raw.lineSequence().filter { it.isNotEmpty() }.forEach { line ->
            require('=' in line)
            val key = line.substringBefore('=')
            val value = line.substringAfter('=')
            if (key == "ROUND") {
                require(rounds.size < ROUND_COUNT)
                val windows = value.split('\t').map { parser.parse(NativePayloadCodec.decodeValue(it)) }
                require(windows.size == 3)
                rounds += SrcuTimingRound(windows[0], windows[1], windows[2])
            } else require(fields.put(key, NativePayloadCodec.decodeValue(value)) == null)
        }
        require(fields["VERSION"] == "1" && fields["CLEANUP"] in setOf("0", "1"))
        return SrcuTimingObservation(SrcuTimingCollection.valueOf(requireNotNull(fields["COLLECTION"])),
            rounds, requireNotNull(fields["KERNEL"]), requireNotNull(fields["DETAIL"]), fields["CLEANUP"] == "1",
            fields["FAILED_WINDOW"]?.let(parser::parse))
    }
}
