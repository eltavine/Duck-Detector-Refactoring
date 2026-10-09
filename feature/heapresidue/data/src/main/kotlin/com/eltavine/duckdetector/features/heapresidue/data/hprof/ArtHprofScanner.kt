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

import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueSignal
import java.io.InputStream

internal data class HprofScan(val signals: List<HeapResidueSignal>, val candidates: Int, val bytesRead: Long)

/**
 * Android 16 ART emits each String's synthetic value array immediately after its instance dump.
 *
 * The dump includes boot-image and zygote-space objects, and parsing memory does not grow with
 * it, so the byte budget is generous; the capture deadline bounds the time spent.
 */
internal class ArtHprofScanner(
    private val targets: Set<String>,
    private val maxBytes: Long = 256L * 1024 * 1024,
    private val host: String? = null,
) {
    fun scan(source: InputStream): HprofScan {
        val input = HprofInput(source, maxBytes)
        val state = State(input, StartupArgumentMatcher(targets, host))
        val header = StringBuilder()
        while (true) {
            val byte = input.u1()
            if (byte == 0) break
            if (header.length >= 32) throw HprofFormatException("Invalid HPROF header")
            header.append(byte.toChar())
        }
        if (header.toString() != "JAVA PROFILE 1.0.3") throw HprofFormatException("Unsupported HPROF version")
        input.idSize = input.u4().toInt()
        if (input.idSize != 4 && input.idSize != 8) throw HprofFormatException("Unsupported identifier size")
        input.skip(8)
        var ended = false
        while (true) {
            input.end = maxBytes
            val tag = input.byteOrEof()
            if (tag < 0) break
            if (ended) throw HprofFormatException("Data after heap end")
            input.skip(4)
            val length = input.u4()
            if (length > maxBytes - input.position) throw HprofFormatException("Record exceeds byte limit")
            input.end = input.position + length
            when (tag) {
                0x01 -> state.stringRecord(length)
                0x02 -> state.classLoadRecord(length)
                0x1c -> state.heapRecord()
                0x2c -> { if (length != 0L) throw HprofFormatException("Invalid heap end"); ended = true }
                else -> input.skip(length)
            }
            if (input.position != input.end) throw HprofFormatException("Record length mismatch")
        }
        if (!ended || !state.sawStringClass) throw HprofFormatException("Incomplete ART heap")
        return HprofScan(state.matcher.result(), state.matcher.candidates, input.position)
    }

    private class State(val input: HprofInput, val matcher: StartupArgumentMatcher) {
        private var stringNameId = 0L
        private var valueNameId = 0L
        private var stringClassId = 0L
        // ART mirror::String declares two 32-bit fields before its synthetic value reference.
        // Region/allocation-stack objects may precede the image's CLASS_DUMP. Bootstrap from
        // this audited layout, then require confirmation before returning any evidence.
        private val valueOffset = 8L
        private var pendingArray = 0L
        var sawStringClass = false
            private set

        fun stringRecord(length: Long) {
            if (length < input.idSize) throw HprofFormatException("Short string record")
            val id = input.id()
            val size = length - input.idSize
            if (size == 16L || size == 5L) {
                when (input.ascii(size.toInt())) {
                    "java.lang.String" -> stringNameId = id
                    "value" -> valueNameId = id
                }
            } else input.skip(size)
        }

        fun classLoadRecord(length: Long) {
            if (length != 8L + 2 * input.idSize) throw HprofFormatException("Invalid class load")
            input.skip(4)
            val id = input.id()
            input.skip(4)
            if (input.id() == stringNameId && stringNameId != 0L) stringClassId = id
        }

        fun heapRecord() {
            while (input.position < input.end) {
                val tag = input.u1()
                val array = pendingArray
                pendingArray = 0L
                when (tag) {
                    0x20 -> classDump()
                    0x21 -> instanceDump()
                    0x22 -> { input.skip(input.idSize + 4L); val count = input.u4(); input.skip(input.idSize + count * input.idSize) }
                    0x23, 0xc3 -> primitiveArray(array, tag == 0xc3)
                    0xfe -> input.skip(4L + input.idSize)
                    0x01 -> input.skip(2L * input.idSize)
                    0x02, 0x03, 0x08, 0x8e -> input.skip(input.idSize + 8L)
                    0x04, 0x06 -> input.skip(input.idSize + 4L)
                    0xff, 0x05, 0x07, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x90 -> input.skip(input.idSize.toLong())
                    else -> throw HprofFormatException("Unknown heap subrecord")
                }
            }
        }

        private fun classDump() {
            val id = input.id()
            input.skip(4L + 6 * input.idSize + 4)
            repeat(input.u2()) { input.skip(2); input.skip(input.typeSize(input.u1()).toLong()) }
            repeat(input.u2()) { input.skip(input.idSize.toLong()); input.skip(input.typeSize(input.u1()).toLong()) }
            var offset = 0L
            var declaredValueOffset = -1L
            repeat(input.u2()) {
                val name = input.id()
                val type = input.u1()
                if (id == stringClassId && name == valueNameId && valueNameId != 0L && type == 2) declaredValueOffset = offset
                offset += input.typeSize(type)
            }
            if (id == stringClassId) {
                if (declaredValueOffset != valueOffset) throw HprofFormatException("Unsupported ART String layout")
                sawStringClass = true
            }
        }

        private fun instanceDump() {
            input.skip(input.idSize + 4L)
            val classId = input.id()
            val size = input.u4()
            if (classId == stringClassId) {
                if (valueOffset + input.idSize > size) throw HprofFormatException("Short String instance")
                input.skip(valueOffset)
                pendingArray = input.id()
                input.skip(size - valueOffset - input.idSize)
            } else input.skip(size)
        }

        private fun primitiveArray(expectedId: Long, noData: Boolean) {
            val id = input.id()
            input.skip(4)
            val count = input.u4()
            val type = input.u1()
            val size = input.typeSize(type)
            if (type == 2) throw HprofFormatException("Object type in primitive array")
            if (noData) return
            // Never decode arbitrary byte/char arrays, metadata strings or embedded prefixes.
            if (expectedId == 0L || id != expectedId || (type != 5 && type != 8) || count < 13 || count > 1024) {
                input.skip(count * size)
                return
            }
            val first = if (type == 5) input.u2() else input.u1()
            val second = if (type == 5) input.u2() else input.u1()
            if (first != 45 || second != 45) { input.skip((count - 2) * size); return }
            val value = StringBuilder(count.toInt()).append("--")
            var ascii = true
            repeat(count.toInt() - 2) {
                val c = if (type == 5) input.u2() else input.u1()
                if (c !in 0x20..0x7e) ascii = false
                value.append(c.toChar())
            }
            if (ascii) matcher.accept(value.toString())
        }
    }
}
