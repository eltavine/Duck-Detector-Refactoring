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

package com.eltavine.duckdetector.features.rootmanagers.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryObservation
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryState
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryTarget
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersDetailRowModel

internal fun installerCanaryRows(observation: InstallerCanaryObservation): List<RootManagersDetailRowModel> {
    val value = when (observation.state) {
        InstallerCanaryState.DISABLED -> "Disabled"
        InstallerCanaryState.UNSUPPORTED -> "Unsupported platform"
        InstallerCanaryState.UNAVAILABLE -> "Unavailable"
        InstallerCanaryState.USER_ACTION_REQUIRED -> "Installation authorization required"
        InstallerCanaryState.THROTTLED -> "Rate limited"
        InstallerCanaryState.TIMED_OUT -> "Timed out"
        InstallerCanaryState.INCONCLUSIVE -> "Inconclusive"
        InstallerCanaryState.UNEXPECTED_SUCCESS -> "Unexpected success; experiment disabled"
        InstallerCanaryState.PERMISSION_OWNER_OBSERVED -> "Permission owner observed"
        InstallerCanaryState.PERMISSION_NOT_OBSERVED -> "Permission conflict not observed"
    }
    val diagnostic = buildString {
        appendLine("Installer permission-owner observation: ${observation.state}")
        appendLine("Candidate permission: ${InstallerCanaryTarget.PERMISSION}")
        observation.ownerPackageName?.let { appendLine("Registry owner: $it (identity unverified)") }
        observation.detail?.let { appendLine(it) }
        observation.locations.forEach { appendLine("Directory observation: user=${it.userId}, uid=${it.uid}, appId=${it.appId}") }
        if (observation.ownerPackageName != null) {
            appendLine("Directory search: user IDs 0–999; not exhaustive. Failed stat does not establish absence.")
            appendLine("Directory errno counts: ${observation.directoryErrors}")
        }
        append("A rebuilt permission may differ; no result establishes root access or execution history.")
    }
    val status = DetectorStatus.info(if (observation.state == InstallerCanaryState.UNEXPECTED_SUCCESS) InfoKind.ERROR else InfoKind.SUPPORT)
    return buildList {
        add(RootManagersDetailRowModel("Installer permission probe", value,
            status, detail = observation.detail, hiddenCopyText = diagnostic))
        observation.ownerPackageName?.let { owner ->
            add(RootManagersDetailRowModel("Candidate permission owner", owner,
                DetectorStatus.info(InfoKind.SUPPORT),
                detail = "Identity unverified. Permission ownership alone does not establish a root manager.", hiddenCopyText = diagnostic))
            val coordinates = observation.locations.joinToString("; ") { "user ${it.userId} · UID ${it.uid}" }
            add(RootManagersDetailRowModel("Owner directory coordinates", coordinates.ifEmpty { "Not observable" },
                DetectorStatus.info(InfoKind.SUPPORT),
                detail = "User IDs 0–999 searched. Mount namespaces and access restrictions can hide existing directories.", hiddenCopyText = diagnostic))
        }
    }
}
