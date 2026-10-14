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

package com.eltavine.duckdetector.features.update.presentation

import com.eltavine.duckdetector.features.update.domain.AvailableNightlyUpdate
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateManifest

enum class UpdateCheckStatus {
    IDLE,
    CHECKING,
    CURRENT,
    AVAILABLE,
    FAILED,
}

sealed interface UpdateDownloadResolution {
    data class Ready(val update: AvailableNightlyUpdate) : UpdateDownloadResolution

    data object Refreshed : UpdateDownloadResolution

    data object Current : UpdateDownloadResolution

    data object Failed : UpdateDownloadResolution
}

sealed interface UpdateDownloadState {
    data object Idle : UpdateDownloadState

    data class Downloading(val manifest: NightlyUpdateManifest, val progress: UpdateDownloadProgress) : UpdateDownloadState

    /** The verified APK on local storage, waiting for the user to confirm the install. */
    data class Ready(val manifest: NightlyUpdateManifest, val apkPath: String) : UpdateDownloadState

    data class Failed(val manifest: NightlyUpdateManifest) : UpdateDownloadState
}

data class UpdateUiState(
    val status: UpdateCheckStatus = UpdateCheckStatus.IDLE,
    val availableUpdate: AvailableNightlyUpdate? = null,
    val isDialogVisible: Boolean = false,
    val download: UpdateDownloadState = UpdateDownloadState.Idle,
)
