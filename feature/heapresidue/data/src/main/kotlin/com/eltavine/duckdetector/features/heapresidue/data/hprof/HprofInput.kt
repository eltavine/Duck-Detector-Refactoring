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

package com.eltavine.duckdetector.features.heapresidue.data.hprof

import com.eltavine.duckdetector.core.evidence.NamedFailure
import java.io.EOFException
import java.io.IOException
import java.io.InputStream

internal class HprofFormatException(message: String) : IOException(message), NamedFailure {
    override val failureName: String = "HprofFormatException"
}

/** Every read and skip consumes the same byte budget and current record boundary. */
internal class HprofInput(private val source: InputStream, private val maxBytes: Long) {
    var position: Long = 0
        private set
    var end: Long = maxBytes
    var idSize: Int = 4
    private val scratch = ByteArray(8192)

    fun byteOrEof(): Int {
        if (position >= maxBytes) {
            if (source.read() < 0) return -1
            throw HprofFormatException("Dump exceeds byte limit")
        }
        if (position >= end) throw HprofFormatException("Read crosses record boundary")
        val value = source.read()
        if (value >= 0) position++
        return value
    }

    fun u1(): Int = byteOrEof().also { if (it < 0) throw EOFException("Truncated HPROF") }
    fun u2(): Int = (u1() shl 8) or u1()
    fun u4(): Long = (u2().toLong() shl 16) or u2().toLong()
    fun id(): Long = if (idSize == 4) u4() else (u4() shl 32) or u4()

    fun skip(count: Long) {
        if (count < 0 || count > end - position || count > maxBytes - position) {
            throw HprofFormatException("Invalid payload length")
        }
        var left = count
        while (left > 0) {
            val n = source.read(scratch, 0, minOf(left, scratch.size.toLong()).toInt())
            if (n < 0) throw EOFException("Truncated HPROF")
            if (n == 0) { u1(); left-- } else { position += n; left -= n }
        }
    }

    fun ascii(length: Int): String {
        val result = StringBuilder(length)
        repeat(length) { result.append(u1().toChar()) }
        return result.toString()
    }

    fun typeSize(type: Int): Int = when (type) {
        2 -> idSize
        4, 8 -> 1
        5, 9 -> 2
        6, 10 -> 4
        7, 11 -> 8
        else -> throw HprofFormatException("Unknown HPROF field type")
    }
}
