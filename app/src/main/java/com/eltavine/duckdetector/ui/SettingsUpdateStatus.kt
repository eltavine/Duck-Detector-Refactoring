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

package com.eltavine.duckdetector.ui

import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUpdateChannel
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUpdateStatus
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.presentation.UpdateCheckStatus

internal fun UpdateCheckStatus.toSettingsUpdateStatus(): SettingsUpdateStatus = when (this) {
    UpdateCheckStatus.IDLE -> SettingsUpdateStatus.IDLE
    UpdateCheckStatus.CHECKING -> SettingsUpdateStatus.CHECKING
    UpdateCheckStatus.CURRENT -> SettingsUpdateStatus.CURRENT
    UpdateCheckStatus.AHEAD -> SettingsUpdateStatus.AHEAD
    UpdateCheckStatus.AVAILABLE -> SettingsUpdateStatus.AVAILABLE
    UpdateCheckStatus.FAILED -> SettingsUpdateStatus.FAILED
}

internal fun UpdateChannel.toSettingsUpdateChannel(): SettingsUpdateChannel = when (this) {
    UpdateChannel.STABLE -> SettingsUpdateChannel.STABLE
    UpdateChannel.NIGHTLY -> SettingsUpdateChannel.NIGHTLY
}

internal fun SettingsUpdateChannel.toUpdateChannel(): UpdateChannel = when (this) {
    SettingsUpdateChannel.STABLE -> UpdateChannel.STABLE
    SettingsUpdateChannel.NIGHTLY -> UpdateChannel.NIGHTLY
}
