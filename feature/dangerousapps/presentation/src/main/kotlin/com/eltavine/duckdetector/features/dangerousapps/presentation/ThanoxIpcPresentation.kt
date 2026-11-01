// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcReport
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcState
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsDetailRowModel

internal fun ThanoxIpcReport.toMethodRow(): DangerousAppsDetailRowModel =
    DangerousAppsDetailRowModel(
        label = "Thanox runtime IPC",
        value = when (state) {
            ThanoxIpcState.NOT_COLLECTED -> "Not collected"
            ThanoxIpcState.NOT_OBSERVED -> "Not observed"
            ThanoxIpcState.MATCHED -> "Compatible runtime interface"
            ThanoxIpcState.UNAVAILABLE -> "Unavailable"
            ThanoxIpcState.INCONCLUSIVE -> "Inconclusive"
        },
        status = when (state) {
            ThanoxIpcState.MATCHED -> DetectorStatus.warning()
            ThanoxIpcState.NOT_OBSERVED -> DetectorStatus.allClear()
            ThanoxIpcState.UNAVAILABLE -> DetectorStatus.info(InfoKind.ERROR)
            ThanoxIpcState.NOT_COLLECTED, ThanoxIpcState.INCONCLUSIVE -> DetectorStatus.info(InfoKind.SUPPORT)
        },
        detail = buildString {
            append(
                when (state) {
                    ThanoxIpcState.NOT_COLLECTED -> "Not collected."
                    ThanoxIpcState.NOT_OBSERVED -> "No compatible runtime service observed."
                    ThanoxIpcState.MATCHED -> "Compatible runtime interface observed; manager APK installation and concealment are unconfirmed."
                    ThanoxIpcState.UNAVAILABLE -> "Probe unavailable; no package presence or concealment is inferred."
                    ThanoxIpcState.INCONCLUSIVE -> "Reply unrecognized; no package presence or concealment is inferred."
                },
            )
            observedDescriptor?.let { append(" Returned interface: $it.") }
            detail?.let { append(" $it") }
        },
    )
