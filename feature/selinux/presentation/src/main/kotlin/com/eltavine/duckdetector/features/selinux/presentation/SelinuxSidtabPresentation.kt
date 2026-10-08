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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabVerdict
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxDetailRowModel

internal fun sidtabRow(result: SelinuxCheckResult): SelinuxDetailRowModel {
    val reading = requireNotNull(result.sidtab)
    return SelinuxDetailRowModel(
        label = result.method,
        value = reading.verdict.label,
        status = reading.status,
        detail = buildString {
            append(sidtabExplanation(reading))
            append(if (reading.attempted) " Captured during app_zygote preload" else " Collection point: app_zygote preload")
            reading.capturedUptimeMs?.let { append(" at boot uptime ${it} ms") }
            append(if (reading.attempted) "; this is a retained measurement, not a live counter check. "
                else "; no measurement was retained. ")
            val details = reading.collectionDetails
            append("Phase=${details.phase}; errno=${details.errno}; child=${details.childEnd}; signal=${details.signal}. ")
            append("Carrier=${details.carrier}; uid=${details.uid}; pid=${details.pid}; kernel=${details.kernelRelease}. ")
            details.failureReason?.let { append(it) }
            reading.rounds.forEachIndexed { index, round ->
                append("\nRound ${index + 1}: entries ${round.beforeControls} → ${round.before} → ")
                append("${round.afterContext} → ${round.afterAttr} → ${round.afterRepeat} → ${round.idleEnd}")
                append("\nControls: positive errno=${round.positiveErrno}, malformed errno=${round.negativeErrno}, ")
                append("malformed attr/current errno=${round.attrNegativeErrno}")
                round.transactions.forEach {
                    append("\n${it.context}: context errno=${it.contextErrno}, attr/current errno=${it.attrErrno}, repeat errno=${it.repeatErrno}")
                }
            }
        },
    )
}

internal fun sidtabExplanation(reading: SelinuxSidtabReading): String = when (reading.verdict) {
    SelinuxSidtabVerdict.DISCREPANCY_OBSERVED ->
        "Two bounded rounds accepted contexts without SID-table growth, then observed growth after rejected attr/current writes. " +
            "This is supporting evidence of a query/registration discrepancy; global activity and hidden policy reloads cannot be excluded. " +
            "It does not identify KernelSU or prove root."
    SelinuxSidtabVerdict.NOT_OBSERVED ->
        "Both rounds observed context-query growth followed by no additional attr/current growth. " +
            "No discrepancy was observed; synchronized hiding implementations can produce this result."
    SelinuxSidtabVerdict.INCONCLUSIVE ->
        "The experiment did not establish a repeatable paired pattern with quiet controls. No integrity conclusion was drawn."
    SelinuxSidtabVerdict.PERMISSION_LIMITED -> "The experiment was limited by permission denial."
    SelinuxSidtabVerdict.UNSUPPORTED -> "The carrier identity or stock MLS candidates did not meet this experiment's requirements."
    SelinuxSidtabVerdict.UNAVAILABLE -> "The experiment could not produce a usable observation."
    SelinuxSidtabVerdict.NOT_COLLECTED -> "No SID-table experiment was captured by this carrier."
}
