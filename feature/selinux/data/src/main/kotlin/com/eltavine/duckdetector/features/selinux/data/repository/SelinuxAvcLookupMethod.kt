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

package com.eltavine.duckdetector.features.selinux.data.repository

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupPayload
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxAvcLookupState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupCollection
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupCollectionDetails
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle

internal fun buildAvcLookupMethod(snapshot: SelinuxAvcLookupSnapshot): SelinuxCheckResult {
    val reading = SelinuxAvcLookupReading(
        collection = when (snapshot.state) {
            SelinuxAvcLookupState.NOT_COLLECTED -> SelinuxAvcLookupCollection.NOT_COLLECTED
            SelinuxAvcLookupState.COLLECTED -> SelinuxAvcLookupCollection.COLLECTED
            SelinuxAvcLookupState.TIMING_ONLY -> SelinuxAvcLookupCollection.TIMING_ONLY
            SelinuxAvcLookupState.PERMISSION_LIMITED -> SelinuxAvcLookupCollection.PERMISSION_LIMITED
            SelinuxAvcLookupState.UNSUPPORTED -> SelinuxAvcLookupCollection.UNSUPPORTED
            SelinuxAvcLookupState.UNAVAILABLE -> SelinuxAvcLookupCollection.UNAVAILABLE
            SelinuxAvcLookupState.INCONCLUSIVE -> SelinuxAvcLookupCollection.INCONCLUSIVE
        },
        writesPerBatch = snapshot.writesPerBatch,
        batchesA = snapshot.batchesA,
        batchesB = snapshot.batchesB,
        completedRounds = snapshot.rounds,
        pairs = snapshot.pairs,
        medianANs = snapshot.medianANs,
        medianBNs = snapshot.medianBNs,
        medianDeltaNs = snapshot.medianDeltaNs,
        details = SelinuxAvcLookupCollectionDetails(
            step = snapshot.step?.name,
            errno = snapshot.errno,
            unexpectedWrite = snapshot.unexpectedPayload.takeIf { it != SelinuxAvcLookupPayload.NONE }
                ?.let { "${it.name} returned ${snapshot.unexpectedReturned}" },
            identityChanged = snapshot.identityChanged,
            childEnd = snapshot.childEnd?.name,
            childExitStatus = snapshot.childExitStatus,
            childSignal = snapshot.childSignal,
            childErrno = snapshot.childErrno,
            cpu = snapshot.cpu,
            cpuRow = snapshot.cpuRow,
            cpuRows = snapshot.cpuRows,
            possibleCpus = snapshot.possibleCpus,
            failureReason = snapshot.failureReason,
        ),
    )
    return SelinuxCheckResult(
        method = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS.label,
        status = reading.label,
        isSecure = null,
        permissionDenied = reading.collection == SelinuxAvcLookupCollection.PERMISSION_LIMITED,
        oracle = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS,
        avcLookup = reading,
    )
}
