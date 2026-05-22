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

package com.eltavine.duckdetector.features.lsposed.data.art

internal object ArtMethodSentinel {
    private const val STATIC_MASK = 0x5A17
    private const val VIRTUAL_OFFSET = 0x3311
    private const val STRING_SUFFIX = "art"

    @JvmStatic
    fun staticToken(value: Int): Int {
        return value xor STATIC_MASK
    }

    fun virtualToken(value: Int): Int {
        return value + VIRTUAL_OFFSET
    }

    @JvmStatic
    fun stringToken(value: String): String {
        return "$value:$STRING_SUFFIX"
    }

    const val STATIC_INPUT = 0x1357
    const val STATIC_EXPECTED = STATIC_INPUT xor STATIC_MASK
    const val VIRTUAL_INPUT = 0x2468
    const val VIRTUAL_EXPECTED = VIRTUAL_INPUT + VIRTUAL_OFFSET
    const val STRING_INPUT = "duck"
    const val STRING_EXPECTED = "$STRING_INPUT:$STRING_SUFFIX"
}
