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

package com.eltavine.duckdetector.features.deviceinfo.ui

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.core.report.DeviceReport
import com.eltavine.duckdetector.core.ui.detector.DeviceProfileFeature
import com.eltavine.duckdetector.core.ui.detector.DeviceProfileSession
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoScanner
import com.eltavine.duckdetector.features.deviceinfo.presentation.toDeviceReport
import com.eltavine.duckdetector.features.deviceinfo.ui.card.DeviceInfoCard

class DeviceInfoProfileFeature(
    private val createScanner: (Context) -> DeviceInfoScanner,
) : DeviceProfileFeature {
    @Composable
    override fun rememberSession(): DeviceProfileSession {
        val context = LocalContext.current
        val viewModel: DeviceInfoViewModel = viewModel(
            factory = remember(context) { DeviceInfoViewModel.factory { createScanner(context.applicationContext) } },
        )
        return remember(viewModel) { DeviceInfoProfileSession(viewModel) }
    }
}

private class DeviceInfoProfileSession(
    private val viewModel: DeviceInfoViewModel,
) : DeviceProfileSession {
    override fun report(): DeviceReport = viewModel.uiState.value.cardModel.toDeviceReport()

    @Composable
    override fun Card() {
        val state by viewModel.uiState.collectAsStateWithLifecycle()
        DeviceInfoCard(model = state.cardModel)
    }
}
