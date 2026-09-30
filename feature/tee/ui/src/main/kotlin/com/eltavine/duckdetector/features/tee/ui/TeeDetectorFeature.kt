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

package com.eltavine.duckdetector.features.tee.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CloudSync
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.core.scan.DetectorSummary
import com.eltavine.duckdetector.core.ui.detector.ConsentCard
import com.eltavine.duckdetector.core.ui.detector.ConsentPrompt
import com.eltavine.duckdetector.core.ui.detector.ConsentSetting
import com.eltavine.duckdetector.core.ui.detector.DetectorFeature
import com.eltavine.duckdetector.core.ui.detector.DetectorSession
import com.eltavine.duckdetector.features.tee.detector.TeeDetector
import com.eltavine.duckdetector.features.tee.detector.TeeRevocationNetworkConsent
import com.eltavine.duckdetector.features.tee.ui.card.TeeDetectorCard
import kotlinx.coroutines.flow.StateFlow

/** The TEE card on the dashboard. */
val detectorFeature: DetectorFeature = TeeDetectorFeature

/**
 * The TEE card keeps expansion and dialog state of its own, so it has a session of its own rather
 * than a CardDetectorFeature; it still scans through [TeeDetector].
 */
internal object TeeDetectorFeature : DetectorFeature {
    override val id: DetectorId = TeeDetector.id

    override val consentCards: List<ConsentCard> = listOf(
        ConsentCard(
            consent = TeeRevocationNetworkConsent,
            prompt = ConsentPrompt(
                icon = Icons.Rounded.CloudSync,
                title = R.string.tee_revocation_network_title,
                headline = R.string.tee_revocation_network_prompt_headline,
                detail = R.string.tee_revocation_network_prompt_detail,
                allowLabel = R.string.tee_revocation_network_allow,
                declineLabel = R.string.tee_revocation_network_decline,
                grantedHeadline = R.string.tee_revocation_network_granted_headline,
                grantedDetail = R.string.tee_revocation_network_granted_detail,
                declinedStatus = R.string.tee_revocation_network_declined_status,
                declinedHeadline = R.string.tee_revocation_network_declined_headline,
                declinedDetail = R.string.tee_revocation_network_declined_detail,
            ),
            setting = ConsentSetting(
                icon = Icons.Rounded.CloudSync,
                title = R.string.tee_revocation_network_setting_title,
                summary = R.string.tee_revocation_network_setting_summary,
                footer = R.string.tee_revocation_network_setting_footer,
            ),
        ),
    )

    @Composable
    override fun rememberSession(): DetectorSession {
        val context = LocalContext.current
        val viewModel: TeeViewModel = viewModel(
            factory = remember(context) {
                TeeViewModel.factory { TeeDetector.createScanner(context.applicationContext) }
            },
        )
        return remember(viewModel) { TeeDetectorSession(viewModel) }
    }
}

private class TeeDetectorSession(
    private val viewModel: TeeViewModel,
) : DetectorSession {
    override val id: DetectorId = TeeDetector.id

    override val summary: StateFlow<DetectorSummary> = viewModel.summary

    override fun report(): DetectorReport = TeeDetector.export(viewModel.uiState.value.cardModel)

    override fun rescan() {
        viewModel.rescan()
    }

    @Composable
    override fun Card() {
        val state by viewModel.uiState.collectAsState()
        TeeDetectorCard(
            model = state.cardModel,
            showDetailsDialog = state.showDetailsDialog,
            showCertificatesDialog = state.showCertificatesDialog,
            onExpandedChange = viewModel::onExpandedChange,
            onFooterAction = viewModel::onFooterAction,
            onDismissDetails = viewModel::dismissDetails,
            onDismissCertificates = viewModel::dismissCertificates,
        )
    }
}
