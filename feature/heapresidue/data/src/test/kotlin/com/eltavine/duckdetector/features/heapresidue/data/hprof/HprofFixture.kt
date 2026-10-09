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

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/** Small binary fixtures exercise record boundaries, not text-shaped stand-ins for a heap. */
internal class HprofFixture(private val idSize: Int = 4, private val classFirst: Boolean = true, private val fieldBytes: Int = 8) {
    private val bytes = ByteArrayOutputStream()
    private val output = DataOutputStream(bytes)
    private var nextId = 10L
    init {
        output.writeBytes("JAVA PROFILE 1.0.3\u0000")
        output.writeInt(idSize)
        output.writeLong(0)
        record(1) { id(1); writeBytes("java.lang.String") }
        record(1) { id(2); writeBytes("value") }
        record(2) { writeInt(1); id(3); writeInt(0); id(1) }
        if (classFirst) classRecord()
    }
    private fun classRecord() {
        record(0x1c) {
            writeByte(0x20); id(3); writeInt(0); repeat(6) { id(0) }; writeInt(16)
            writeShort(0); writeShort(0); writeShort(fieldBytes / 4 + 1)
            repeat(fieldBytes / 4) { id(4L + it); writeByte(10) }
            id(2); writeByte(2)
        }
    }
    fun string(value: String, wide: Boolean = false, linked: Boolean = true, wrongId: Boolean = false): HprofFixture {
        val instanceId = nextId++
        val arrayId = nextId++
        record(0x1c) {
            if (linked) {
                writeByte(0x21); id(instanceId); writeInt(0); id(3); writeInt(fieldBytes + idSize); repeat(fieldBytes / 4) { writeInt(0) }; id(arrayId)
            }
            writeByte(0x23); id(if (wrongId) arrayId + 10000 else arrayId); writeInt(0); writeInt(value.length); writeByte(if (wide) 5 else 8)
            if (wide) value.forEach { writeShort(it.code) } else writeBytes(value)
        }
        return this
    }
    fun metadata(value: String): HprofFixture { record(1) { id(123); writeBytes(value) }; return this }
    fun unknownHeapTag(): HprofFixture { record(0x1c) { writeByte(0x66) }; return this }
    fun finish(end: Boolean = true): ByteArray { if (!classFirst) classRecord(); if (end) record(0x2c) {}; return bytes.toByteArray() }
    private fun DataOutputStream.id(value: Long) { if (idSize == 4) writeInt(value.toInt()) else writeLong(value) }
    private fun record(tag: Int, body: DataOutputStream.() -> Unit) {
        val buffer = ByteArrayOutputStream(); DataOutputStream(buffer).body()
        output.writeByte(tag); output.writeInt(0); output.writeInt(buffer.size()); output.write(buffer.toByteArray())
    }
}
