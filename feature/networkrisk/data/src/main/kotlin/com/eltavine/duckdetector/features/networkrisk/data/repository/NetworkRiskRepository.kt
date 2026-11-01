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

package com.eltavine.duckdetector.features.networkrisk.data.repository

import android.content.Context
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.evidence.FailureName
import com.eltavine.duckdetector.features.networkrisk.data.network.AndroidNetworkCollector
import com.eltavine.duckdetector.features.networkrisk.data.clients.NetworkClientCollector
import com.eltavine.duckdetector.features.networkrisk.data.modules.Box4MagiskCollector
import com.eltavine.duckdetector.features.networkrisk.data.modules.BoxForRootCollector
import com.eltavine.duckdetector.features.networkrisk.domain.NetworkRiskReport
import com.eltavine.duckdetector.features.networkrisk.domain.NetworkRiskStage
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class NetworkRiskRepository(context: Context) : DetectorScanner<NetworkRiskReport> {
    private val appContext = context.applicationContext

    override suspend fun scan(): NetworkRiskReport = withContext(Dispatchers.IO) {
        try {
            NetworkRiskReport(
                stage = NetworkRiskStage.READY,
                network = AndroidNetworkCollector(appContext).collect(),
                clients = NetworkClientCollector(appContext).collect(),
                modules = listOf(Box4MagiskCollector().collect(), BoxForRootCollector().collect()),
            )
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            NetworkRiskReport.failed(FailureName.describe(failure))
        }
    }
}
