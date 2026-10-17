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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

internal data class UidTaskSnapshot(
    val status: Int,
    val checked: Int = 0,
    val error: Int = 0,
    val tasks: Map<Int, Int> = emptyMap(),
    val failure: String = "",
)

internal class HmaUidTaskBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    fun scan(firstUid: Int, lastUid: Int): UidTaskSnapshot = collector.collect(
        readPayload = { nativeScan(firstUid, lastUid) },
        parse = { parse(it, firstUid, lastUid) },
        unavailable = { UidTaskSnapshot(FAILURE, failure = it.detail) },
    )

    private external fun nativeScan(firstUid: Int, lastUid: Int): IntArray

    companion object {
        const val COMPLETE = 0
        const val PARTIAL = 1
        const val RESTRICTED = 2
        const val SIGNALED = 3
        const val TIMEOUT = 4
        const val FAILURE = 5

        internal fun parse(values: IntArray, firstUid: Int, lastUid: Int): UidTaskSnapshot {
            require(values.size >= 6 && values[0] == 1)
            val status = values[1]
            val checked = values[2]
            val error = values[3]
            val count = values[5]
            require(status in COMPLETE..FAILURE && count in 0..512 && values.size == 6 + count * 2)
            require(firstUid >= 0 && firstUid <= lastUid && lastUid.toLong() - firstUid <= 9999)
            require(checked in 0..(lastUid - firstUid + 1))
            require(count <= checked)
            if (status == COMPLETE) require(checked == lastUid - firstUid + 1)
            if (status == COMPLETE || status == PARTIAL) require(values[4] in 1..40 && error == 0)
            val tasks = linkedMapOf<Int, Int>()
            var previous = firstUid - 1
            repeat(count) { index ->
                val uid = values[6 + index * 2]
                val rawPriority = values[7 + index * 2]
                require(uid > previous && uid.toLong() < firstUid.toLong() + checked && rawPriority in 1..40)
                tasks[uid] = 20 - rawPriority
                previous = uid
            }
            return UidTaskSnapshot(status, checked, error, tasks)
        }
    }
}
