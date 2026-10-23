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

package com.eltavine.duckdetector.features.adbruntime.data.repository

import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import org.junit.Assert.assertEquals
import org.junit.Test

class AdbJdwpSocketProbeTest {
    @Test
    fun aMatchingListenerDeniesTheConnect() {
        for (errno in listOf(AdbStatErrno.EACCES, AdbStatErrno.EPERM)) {
            assertEquals(AdbProbeState.OBSERVED, classifyAbstractConnect(errno))
        }
    }

    @Test
    fun aReachableListenerIsReportedAsSuch() {
        assertEquals(AdbProbeState.OBSERVED, classifyAbstractConnect(0))
    }

    @Test
    fun aRefusalIsAbsence() {
        for (errno in listOf(AdbStatErrno.ECONNREFUSED, AdbStatErrno.ENOENT)) {
            assertEquals(AdbProbeState.NOT_OBSERVED, classifyAbstractConnect(errno))
        }
    }

    @Test
    fun nonblockingConnectIsIndeterminateWhenTheBacklogIsFullOrInterrupted() {
        for (errno in listOf(AdbStatErrno.EAGAIN, AdbStatErrno.EINPROGRESS, AdbStatErrno.EINTR)) {
            assertEquals(AdbProbeState.UNAVAILABLE, classifyAbstractConnect(errno))
        }
    }

    @Test
    fun unexpectedResultsStayUnknown() {
        assertEquals(AdbProbeState.UNAVAILABLE, classifyAbstractConnect(null))
        assertEquals(AdbProbeState.UNAVAILABLE, classifyAbstractConnect(95))
    }

}
