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

import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxSidtabErrno
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxSidtabChildEnd
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxSidtabStep
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxSidtabSnapshot
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxSidtabCollection as Collection
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabCollection
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabRound
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabTransaction
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabCollectionDetails

internal fun buildSidtabMethod(snapshot: SelinuxSidtabSnapshot): SelinuxCheckResult {
    val reading = SelinuxSidtabReading(
        collection = when (snapshot.collection) {
            Collection.NOT_COLLECTED -> SelinuxSidtabCollection.NOT_COLLECTED
            Collection.COMPLETE -> SelinuxSidtabCollection.COMPLETE
            Collection.UNSUPPORTED -> SelinuxSidtabCollection.UNSUPPORTED
            Collection.PERMISSION_LIMITED -> SelinuxSidtabCollection.PERMISSION_LIMITED
            Collection.UNAVAILABLE -> SelinuxSidtabCollection.UNAVAILABLE
            Collection.INCONCLUSIVE -> SelinuxSidtabCollection.INCONCLUSIVE
        },
        attempted = snapshot.attempted,
        completedRounds = snapshot.completedRounds,
        carrierVerified = snapshot.carrierContext == "u:r:app_zygote:s0" &&
            (snapshot.uid ?: -1) >= 10000 && snapshot.childEnd == SelinuxSidtabChildEnd.EXITED &&
            snapshot.step == SelinuxSidtabStep.FINISHED &&
            snapshot.errno == 0 && snapshot.signal == 0,
        canonicalMismatch = snapshot.canonicalMismatch,
        identityChanged = snapshot.identityChanged,
        capturedUptimeMs = snapshot.capturedUptimeMs,
        rounds = snapshot.rounds.map { round ->
            SelinuxSidtabRound(
                beforeControls = round.beforeControls,
                before = round.before,
                afterContext = round.afterContext,
                afterAttr = round.afterAttr,
                afterRepeat = round.afterRepeat,
                idleEnd = round.idleEnd,
                controlsPassed = round.positiveErrno == 0 && round.negativeErrno == SelinuxSidtabErrno.INVALID_ARGUMENT.code,
                contexts = round.samples.map { it.context },
                contextWritesAccepted = round.samples.all { it.contextErrno == 0 },
                attrWritesRejected = round.samples.all {
                    it.attrErrno == SelinuxSidtabErrno.PERMISSION_DENIED.code ||
                        it.attrErrno == SelinuxSidtabErrno.OPERATION_NOT_PERMITTED.code
                },
                repeatWritesAccepted = round.samples.all { it.repeatErrno == 0 },
                transactions = round.samples.map { SelinuxSidtabTransaction(it.context, it.contextErrno, it.attrErrno, it.repeatErrno) },
                positiveErrno = round.positiveErrno,
                negativeErrno = round.negativeErrno,
                stockContextsVerified = round.samples.size == 4 &&
                    round.samples.all { it.context.startsWith("u:r:app_zygote:s0:c") },
            )
        },
        collectionDetails = SelinuxSidtabCollectionDetails(
            phase = snapshot.step.name,
            errno = snapshot.errno,
            childEnd = snapshot.childEnd?.name,
            signal = snapshot.signal,
            carrier = snapshot.carrierContext,
            uid = snapshot.uid,
            pid = snapshot.pid,
            kernelRelease = snapshot.kernelRelease,
            failureReason = snapshot.failureReason,
        ),
    )
    return SelinuxCheckResult(
        method = SelinuxOracle.SIDTAB_CONSISTENCY.label,
        status = reading.verdict.label,
        isSecure = null,
        permissionDenied = snapshot.collection == Collection.PERMISSION_LIMITED,
        oracle = SelinuxOracle.SIDTAB_CONSISTENCY,
        sidtab = reading,
    )
}
