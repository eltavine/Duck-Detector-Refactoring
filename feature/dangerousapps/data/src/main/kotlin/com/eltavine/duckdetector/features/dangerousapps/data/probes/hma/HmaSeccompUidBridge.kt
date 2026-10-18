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

internal data class UidSeccompSnapshot(
    val installStatus: Int = HmaSeccompUidBridge.FAILURE,
    val installError: Int = 0,
    val kernelMajor: Int = 0,
    val kernelMinor: Int = 0,
    val queried: Int = 0,
    val notified: Int = 0,
    val firstSuppressed: Int = -1,
    val lastSuppressed: Int = -1,
    val queryOutcome: Int = HmaSeccompUidBridge.QUERY_NOT_RUN,
    val queryError: Int = 0,
    val selfNotified: Boolean = false,
    val failure: String = "",
)

internal class HmaSeccompUidBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    fun probe(firstUid: Int, lastUid: Int): UidSeccompSnapshot = collector.collect(
        readPayload = { nativeProbe(firstUid, lastUid) },
        parse = { parse(it, firstUid, lastUid) },
        unavailable = { UidSeccompSnapshot(failure = it.detail) },
    )

    private external fun nativeProbe(firstUid: Int, lastUid: Int): IntArray

    companion object {
        const val INSTALLED = 0
        const val FOREIGN_LISTENER = 1
        const val UNSUPPORTED = 2
        const val RESTRICTED = 3
        const val FAILURE = 4
        const val INSTALL_TRAPPED = 5

        const val QUERY_COMPLETE = 0
        const val QUERY_TRAPPED = 1
        const val QUERY_SIGNALED = 2
        const val QUERY_TIMEOUT = 3
        const val QUERY_FAILURE = 4
        const val QUERY_NOT_RUN = 5

        private const val VERSION = 1
        private const val MAX_SPAN = 10000

        /**
         * The native payload is a versioned integer array. An installed listener either completes
         * the whole range or reports that observation stopped; a partial notification count is not
         * turned into a suppression claim. [selfNotified] is a control for a completed clean run:
         * the caller's own UID is inside the queried range, so a clean run must have notified it.
         */
        internal fun parse(values: IntArray, firstUid: Int, lastUid: Int): UidSeccompSnapshot {
            require(values.size == 12 && values[0] == VERSION)
            require(firstUid >= 0 && firstUid <= lastUid &&
                lastUid.toLong() - firstUid < MAX_SPAN)
            val span = lastUid - firstUid + 1
            val installStatus = values[1]
            val installError = values[2]
            val kernelMajor = values[3]
            val kernelMinor = values[4]
            val queried = values[5]
            val notified = values[6]
            val firstSuppressed = values[7]
            val lastSuppressed = values[8]
            val queryOutcome = values[9]
            val queryError = values[10]
            val selfNotified = values[11]
            require(installStatus in INSTALLED..INSTALL_TRAPPED)
            require(kernelMajor >= 0 && kernelMinor >= 0)
            require(queried in 0..span && notified in 0..span)
            require(queryOutcome in QUERY_COMPLETE..QUERY_NOT_RUN)
            require(selfNotified == 0 || selfNotified == 1)
            if (installStatus == FOREIGN_LISTENER) require(installError == 16)
            if (installStatus == INSTALL_TRAPPED) require(installError == 31)
            if (queryOutcome == QUERY_TRAPPED) require(queryError == 31)
            if (installStatus == INSTALLED) {
                require(installError == 0)
                when (queryOutcome) {
                    QUERY_COMPLETE -> {
                        require(queried == span && notified <= queried && queryError == 0)
                        if (notified == queried) {
                            require(firstSuppressed == -1 && lastSuppressed == -1)
                            require(selfNotified == 1)
                        } else {
                            require(firstSuppressed in firstUid..lastUid)
                            require(lastSuppressed in firstSuppressed..lastUid)
                            val missing = queried - notified
                            require(missing <= lastSuppressed - firstSuppressed + 1)
                            if (missing == 1) require(firstSuppressed == lastSuppressed)
                            if (notified == 0) require(firstSuppressed == firstUid && lastSuppressed == lastUid)
                        }
                    }

                    QUERY_TRAPPED, QUERY_SIGNALED, QUERY_TIMEOUT, QUERY_FAILURE ->
                        require(queried == 0 && firstSuppressed == -1 && lastSuppressed == -1)

                    else -> throw IllegalArgumentException("Installed listener without a query result.")
                }
            } else {
                require(queried == 0 && notified == 0)
                require(firstSuppressed == -1 && lastSuppressed == -1)
                require(queryOutcome == QUERY_NOT_RUN)
                require(selfNotified == 0)
            }
            return UidSeccompSnapshot(
                installStatus = installStatus,
                installError = installError,
                kernelMajor = kernelMajor,
                kernelMinor = kernelMinor,
                queried = queried,
                notified = notified,
                firstSuppressed = firstSuppressed,
                lastSuppressed = lastSuppressed,
                queryOutcome = queryOutcome,
                queryError = queryError,
                selfNotified = selfNotified == 1,
            )
        }
    }
}
