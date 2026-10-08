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

import com.eltavine.duckdetector.core.native.DuckDetectorNativeLibrary
import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuCloseSample
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuCloseStage
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingWindow

internal class SrcuTimingNativeBridge {
    fun measure(directory: String, trigger: Runnable): SrcuTimingWindow {
        check(DuckDetectorNativeLibrary.isLoaded) { "Native library unavailable" }
        return parse(nativeMeasureWindow(directory, trigger))
    }
    internal fun parse(raw: String): SrcuTimingWindow {
        require(raw.length <= 32_768) { "Oversized close window" }
        val lines = raw.lineSequence().filter { it.isNotEmpty() }.toList()
        val fields = mutableMapOf<String, String>()
        val samples = mutableListOf<SrcuCloseSample>()
        for (line in lines) {
            require('=' in line) { "Malformed close field" }
            val key = line.substringBefore('=')
            val value = line.substringAfter('=')
            if (key == "SAMPLE") {
                val parts = value.split('\t').map(NativePayloadCodec::decodeValue)
                require(parts.size == 4 && samples.size < 128)
                val stage = parts[2].toInt()
                require(stage in SrcuCloseStage.entries.indices)
                samples += SrcuCloseSample(parts[0].toLong(), parts[1].toLong(),
                    SrcuCloseStage.entries[stage], parts[3].toInt().also { require(it >= 0) })
            } else {
                require(fields.put(key, NativePayloadCodec.decodeValue(value)) == null) { "Duplicate close field" }
            }
        }
        require(fields["VERSION"] == "1" && fields["COUNT"]?.toInt() == samples.size)
        require(fields["SATURATED"] in setOf("0", "1"))
        return SrcuTimingWindow(requireNotNull(fields["BEGIN"]).toLong(),
            requireNotNull(fields["END"]).toLong(), fields["SATURATED"] == "1", samples)
    }
    private external fun nativeMeasureWindow(directory: String, trigger: Runnable): String
}
