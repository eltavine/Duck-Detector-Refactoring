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

package com.eltavine.duckdetector.core.native

/**
 * The Kotlin half of the wire format shared by every native snapshot bridge.
 *
 * Payloads are newline-separated `KEY=value` records, where multi-column records join their columns
 * with tabs. That layout only holds if the four characters carrying structural meaning are escaped,
 * so a value may never contain a raw backslash, newline, carriage return, or tab:
 *
 * | raw  | wire  |
 * |------|-------|
 * | `\`  | `\\`  |
 * | LF   | `\n`  |
 * | CR   | `\r`  |
 * | TAB  | `\t`  |
 *
 * The C++ half lives in `cpp/common/payload_codec.h` and `NativePayloadCodecTest` pins the two
 * against each other. Keeping both sides on one table is what makes splitting a record on a raw
 * `\t` safe, and it is why an unescaped encoder silently truncates evidence rather than failing
 * loudly.
 */
object NativePayloadCodec {

    private const val ESCAPE = '\\'

    fun encodeValue(value: String): String {
        if (value.none(::requiresEscape)) {
            return value
        }
        return buildString(value.length) {
            value.forEach { character ->
                when (character) {
                    ESCAPE -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(character)
                }
            }
        }
    }

    /**
     * Reverses [encodeValue] in a single pass.
     *
     * A chain of `replace` calls cannot do this correctly: decoding `\\n` (an escaped backslash
     * followed by the letter n) would first become a real backslash and then be re-read as a
     * newline escape. Scanning left to right consumes each escape exactly once.
     *
     * An unrecognised escape is emitted verbatim rather than dropped, so a payload produced by a
     * newer native layer that adds an escape stays readable to an older parser instead of losing
     * the character.
     */
    fun decodeValue(encoded: String): String {
        if (!encoded.contains(ESCAPE)) {
            return encoded
        }
        return buildString(encoded.length) {
            var index = 0
            while (index < encoded.length) {
                val character = encoded[index]
                if (character != ESCAPE || index == encoded.lastIndex) {
                    append(character)
                    index++
                    continue
                }
                when (val escaped = encoded[index + 1]) {
                    ESCAPE -> append(ESCAPE)
                    'n' -> append('\n')
                    'r' -> append('\r')
                    't' -> append('\t')
                    else -> {
                        append(character)
                        append(escaped)
                    }
                }
                index += 2
            }
        }
    }

    private fun requiresEscape(character: Char): Boolean {
        return character == ESCAPE || character == '\n' || character == '\r' || character == '\t'
    }
}
