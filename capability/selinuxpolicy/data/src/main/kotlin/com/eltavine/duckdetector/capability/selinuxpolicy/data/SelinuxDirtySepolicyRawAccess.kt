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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.FileInputStream
import java.io.IOException
import java.io.RandomAccessFile

internal object SelinuxRawAccess {
    data class Decision(val allowed: UInt, val seqno: Long, val flags: UInt)
    class TransactionFailure(val stage: String, val errorCode: Int?, val count: Int?, cause: Throwable) :
        IOException("$stage: ${cause.message}", cause)

    fun classId(name: String): Int = readIndex("/sys/fs/selinux/class/$name/index")

    fun permissionMask(clazz: String, permission: String): UInt {
        val index = readIndex("/sys/fs/selinux/class/$clazz/perms/$permission")
        require(index in 1..32) { "Invalid SELinux permission bit: $index" }
        return 1u shl (index - 1)
    }

    private fun readIndex(path: String): Int = FileInputStream(path).use { stream ->
        stream.bufferedReader().readText().trim().toInt()
    }

    fun query(source: String, target: String, clazz: Int): String {
        val access = try {
            RandomAccessFile("/sys/fs/selinux/access", "rw")
        } catch (error: IOException) {
            throw TransactionFailure("open", null, null, error)
        }
        return access.use {
            val request = "$source $target $clazz".toByteArray(Charsets.UTF_8)
            val written = try {
                Os.write(access.fd, request, 0, request.size)
            } catch (error: ErrnoException) {
                throw TransactionFailure("write", error.errno, null, error)
            }
            if (written != request.size) {
                throw TransactionFailure("write", null, written, IOException("SELinux access request short write: $written/${request.size}"))
            }
            val buffer = ByteArray(256)
            val count = try {
                access.read(buffer)
            } catch (error: IOException) {
                throw TransactionFailure("read", null, null, error)
            }
            if (count <= 0) throw TransactionFailure("read", null, count, IOException("Empty SELinux access response"))
            String(buffer, 0, count, Charsets.UTF_8)
        }
    }

    fun parse(raw: String): Decision? {
        val fields = raw.trimEnd('\n').split(' ')
        if (fields.size != 6) return null
        if (listOf(0, 1, 2, 3, 5).any { fields[it].toUIntOrNull(16) == null }) return null
        val seqno = fields[4].toUIntOrNull() ?: return null
        return Decision(fields[0].toUInt(16), seqno.toLong(), fields[5].toUInt(16))
    }

    /** Like DirtySepolicy's first contextExists step; EINVAL means an invalid context. */
    fun contextNode(context: String): String {
        if (SelinuxContextValidityBridge.isNativeLibraryLoaded) {
            return nativeContextNode(context)
        }
        // DirtySepolicy also supports the Kotlin-only carrier when JNI is unavailable.
        val fd = try {
            Os.open("/sys/fs/selinux/context", OsConstants.O_WRONLY or OsConstants.O_CLOEXEC, 0)
        } catch (error: ErrnoException) {
            return "UNAVAILABLE:open errno=${error.errno}"
        }
        return try {
            val bytes = context.toByteArray(Charsets.UTF_8)
            if (Os.write(fd, bytes, 0, bytes.size) == bytes.size) "VALID" else "UNAVAILABLE:write short_write"
        } catch (error: ErrnoException) {
            if (error.errno == OsConstants.EINVAL) "INVALID" else "UNAVAILABLE:write errno=${error.errno}"
        } finally {
            Os.close(fd)
        }
    }

    fun measureKsuContextTiming(procAttr: Boolean = false): List<Long> {
        if (!SelinuxContextValidityBridge.isNativeLibraryLoaded) return emptyList()
        return runCatching { nativeMeasureKsuContextTiming(procAttr)?.toList().orEmpty() }
            .getOrDefault(emptyList())
    }

    /** Raw app_zygote SELinuxFS two-write transaction record; interpretation belongs to the feature. */
    fun probeXxksuFdReuse(): String? {
        if (!SelinuxContextValidityBridge.isNativeLibraryLoaded) return null
        return runCatching { nativeProbeXxksuFdReuse() }.getOrNull()
    }

    /** Untimed SELinuxFS /access ignored-fourth-field experiment; app_zygote parent only. */
    fun probeXxksuAccessTail(): String? {
        if (!SelinuxContextValidityBridge.isNativeLibraryLoaded) return null
        return runCatching { nativeProbeXxksuAccessTail() }.getOrNull()
    }

    private external fun nativeContextNode(context: String): String

    private external fun nativeMeasureKsuContextTiming(procAttr: Boolean): LongArray?

    private external fun nativeProbeXxksuFdReuse(): String?
    private external fun nativeProbeXxksuAccessTail(): String?
}
