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

import android.os.BadParcelableException
import android.os.IBinder
import android.os.Parcel

/** Parcel.enforceNoDataAvail exists only from API 33; this is the same check on every supported release. */
internal fun Parcel.requireFullyConsumed() {
    val unread = dataAvail()
    if (unread > 0) throw BadParcelableException("Parcel data not fully consumed, unread size: $unread")
}

internal object HeapDumpProtocol {
    const val SERVICE = "com.eltavine.duckdetector.heapresidue.dump"
    const val CALLBACK = "com.eltavine.duckdetector.heapresidue.result"
    const val DUMP = IBinder.FIRST_CALL_TRANSACTION
    const val RESULT = IBinder.FIRST_CALL_TRANSACTION
}

internal enum class HeapDumpStatus(val wire: Int) {
    COMPLETE(0), HIDDEN_API_UNAVAILABLE(1), DUMP_FAILED(2), REUSED_PROCESS(3);
    companion object {
        fun fromWire(value: Int): HeapDumpStatus = entries.firstOrNull { it.wire == value }
            ?: throw IllegalArgumentException("Unknown dump status")
    }
}

internal data class HeapDumpResult(
    val status: HeapDumpStatus,
    val ageMillis: Long = 0,
    val durationMillis: Long = 0,
    val gcCountBefore: Long = -1,
)
