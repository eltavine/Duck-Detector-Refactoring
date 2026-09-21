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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.core.native.NativePayloadCodec

/**
 * Four tab-separated columns carrying one `/proc/self/attr/current` probe result.
 *
 * Columns are escaped with [NativePayloadCodec], the same contract the native bridges use, so a tab
 * inside a value cannot be mistaken for a column boundary. These values come from the kernel and
 * from exception messages, so their contents are not ours to assume.
 */
object SelinuxProcAttrCurrentPayloadCodec {

    fun encode(result: SelinuxProcAttrCurrentResult): String {
        return listOf(
            result.label,
            result.targetContext,
            result.outcomeClass,
            result.rawMessage,
        ).joinToString(FIELD_SEPARATOR, transform = NativePayloadCodec::encodeValue)
    }

    /** Returns `null` when [payload] is not exactly [COLUMN_COUNT] columns, meaning it is not ours. */
    fun decode(payload: String): SelinuxProcAttrCurrentResult? {
        val parts = payload.split(FIELD_SEPARATOR)
        if (parts.size != COLUMN_COUNT) {
            return null
        }
        return SelinuxProcAttrCurrentResult(
            label = NativePayloadCodec.decodeValue(parts[0]),
            targetContext = NativePayloadCodec.decodeValue(parts[1]),
            outcomeClass = NativePayloadCodec.decodeValue(parts[2]),
            rawMessage = NativePayloadCodec.decodeValue(parts[3]),
        )
    }

    private const val FIELD_SEPARATOR = "\t"

    private const val COLUMN_COUNT = 4
}
