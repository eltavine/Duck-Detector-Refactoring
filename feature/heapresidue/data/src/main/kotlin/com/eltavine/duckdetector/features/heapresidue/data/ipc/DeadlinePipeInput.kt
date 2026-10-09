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

package com.eltavine.duckdetector.features.heapresidue.data.ipc

import androidx.annotation.RequiresApi
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.InputStream
import java.net.SocketTimeoutException

/** Nonblocking reads plus finite poll: coroutine cancellation never waits on an unbounded pipe read. */
@RequiresApi(36)
internal class DeadlinePipeInput(
    private val pipe: ParcelFileDescriptor,
    private val deadlineMillis: Long,
    private val checkActive: () -> Unit,
) : InputStream() {
    private val single = ByteArray(1)
    private val poll = StructPollfd().apply {
        fd = pipe.fileDescriptor
        events = OsConstants.POLLIN.toShort()
    }

    private val polls = arrayOf(poll)

    init {
        Os.fcntlInt(pipe.fileDescriptor, OsConstants.F_SETFL,
            Os.fcntlInt(pipe.fileDescriptor, OsConstants.F_GETFL, 0) or OsConstants.O_NONBLOCK)
    }

    override fun read(): Int = if (read(single, 0, 1) < 0) -1 else single[0].toInt() and 255

    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        require(offset >= 0 && length >= 0 && offset <= bytes.size - length)
        if (length == 0) return 0
        while (true) {
            checkActive()
            val remaining = deadlineMillis - SystemClock.elapsedRealtime()
            if (remaining <= 0) throw SocketTimeoutException("Heap capture deadline exceeded")
            try {
                if (Os.poll(polls, minOf(remaining, 250).toInt()) == 0) continue
                val count = Os.read(pipe.fileDescriptor, bytes, offset, length)
                if (count == 0) { pipe.checkError(); return -1 }
                return count
            } catch (failure: ErrnoException) {
                if (failure.errno != OsConstants.EAGAIN && failure.errno != OsConstants.EINTR) throw failure
            }
        }
    }
}
