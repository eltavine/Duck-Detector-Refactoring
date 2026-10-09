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

/**
 * Every read and skip consumes the same byte budget and current record boundary.
 *
 * ART flushes each HPROF record separately and segments the heap every 128 objects, so a dump is
 * mostly small records: values are decoded straight from an owned block buffer and skips only
 * advance it. Refills never take more than maxBytes + 1 bytes from the source.
 */
internal class HprofInput(private val source: InputStream, private val maxBytes: Long) {
    var position: Long = 0
        private set
    var end: Long = maxBytes
    var idSize: Int = 4
    private val buffer = ByteArray(64 * 1024)
    private var index = 0
    private var limit = 0

    fun byteOrEof(): Int {
        if (index < limit && position < end && position < maxBytes) return take()
        if (position >= maxBytes) {
            if (index == limit && !fill()) return -1
            throw HprofFormatException("Dump exceeds byte limit")
        }
        if (position >= end) throw HprofFormatException("Read crosses record boundary")
        if (index == limit && !fill()) return -1
        return take()
    }

    fun u1(): Int = byteOrEof().also { if (it < 0) throw EOFException("Truncated HPROF") }

    fun u2(): Int {
        if (!buffered(2)) return (u1() shl 8) or u1()
        val value = (byteAt(0) shl 8) or byteAt(1)
        consume(2)
        return value
    }

    fun u4(): Long {
        if (!buffered(4)) return (u2().toLong() shl 16) or u2().toLong()
        val value = (byteAt(0).toLong() shl 24) or (byteAt(1).toLong() shl 16) or
            (byteAt(2).toLong() shl 8) or byteAt(3).toLong()
        consume(4)
        return value
    }

    fun id(): Long = if (idSize == 4) u4() else (u4() shl 32) or u4()

    fun skip(count: Long) {
        if (count < 0 || count > end - position || count > maxBytes - position) {
            throw HprofFormatException("Invalid payload length")
        }
        var left = count
        while (left > 0) {
            if (index == limit && !fill()) throw EOFException("Truncated HPROF")
            val n = minOf(left, (limit - index).toLong()).toInt()
            consume(n)
            left -= n
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

    // The fast path applies only where the byte-by-byte path could not fail.
    private fun buffered(count: Int): Boolean =
        limit - index >= count && minOf(end, maxBytes) - position >= count

    private fun byteAt(offset: Int): Int = buffer[index + offset].toInt() and 0xff

    private fun take(): Int = byteAt(0).also { consume(1) }

    private fun consume(count: Int) {
        index += count
        position += count
    }

    // Only called with an empty buffer, when the source has supplied exactly position bytes.
    private fun fill(): Boolean {
        val room = minOf(buffer.size.toLong(), maxBytes + 1 - position).toInt()
        var count = source.read(buffer, 0, room)
        if (count == 0) {
            // A zero-length block read breaks the InputStream contract; take one byte instead.
            val single = source.read()
            if (single >= 0) buffer[0] = single.toByte()
            count = if (single >= 0) 1 else -1
        }
        index = 0
        limit = maxOf(count, 0)
        return count > 0
    }
}
