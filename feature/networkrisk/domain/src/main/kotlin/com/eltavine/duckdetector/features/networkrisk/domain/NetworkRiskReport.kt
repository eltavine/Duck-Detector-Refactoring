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

package com.eltavine.duckdetector.features.networkrisk.domain

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility

enum class NetworkRiskStage { LOADING, READY, FAILED }
enum class ClientIdentity { SIGNATURE_VERIFIED, IDENTITY_UNVERIFIED }
data class NetworkClientEvidence(
    val packageName: String,
    val displayName: String,
    val state: ObservationState,
    val identity: ClientIdentity = ClientIdentity.IDENTITY_UNVERIFIED,
    val version: String? = null,
    val signingState: ObservationState = ObservationState.UNAVAILABLE,
    val signingFailure: ProbeFailure? = null,
)
data class NetworkClientInventory(
    val visibility: InstalledPackageVisibility,
    val state: ObservationState,
    val clients: List<NetworkClientEvidence>,
)
enum class ProxyDeployment { BOX4MAGISK, BOX_FOR_ROOT }
/** Only module.prop is read; deployment metadata does not establish service or traffic state. */
data class ProxyModuleEvidence(
    val deployment: ProxyDeployment,
    val metadata: NetworkObservation<String>,
)
data class NetworkRiskReport(
    val stage: NetworkRiskStage,
    val network: NetworkSampleWindow? = null,
    val clients: NetworkClientInventory? = null,
    val modules: List<ProxyModuleEvidence> = emptyList(),
    val errorMessage: String? = null,
) {
    companion object {
        fun loading(): NetworkRiskReport = NetworkRiskReport(NetworkRiskStage.LOADING)
        fun failed(message: String): NetworkRiskReport = NetworkRiskReport(NetworkRiskStage.FAILED, errorMessage = message)
    }
}
