/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.features.tee.domain

data class TeeReport(
    val stage: TeeScanStage,
    val verdict: TeeVerdict,
    val tier: TeeTier,
    val headline: String,
    val summary: String,
    val collapsedSummary: String,
    val trustRoot: TeeTrustRoot,
    val localTrustChainLevel: TeeSignalLevel = TeeSignalLevel.INFO,
    val trustSummary: String,
    val tamperScore: Int,
    val evidenceCount: Int,
    val supplementaryIndicatorCount: Int = 0,
    val supplementaryReviewLevel: TeeSignalLevel = TeeSignalLevel.INFO,
    val signals: List<TeeSignal>,
    val sections: List<TeeEvidenceSection>,
    val certificates: List<TeeCertificateItem>,
    val rkpState: TeeRkpState = TeeRkpState(),
    val patchState: TeePatchState = TeePatchState(),
    val soterState: TeeSoterState = TeeSoterState(),
    val networkState: TeeNetworkState = TeeNetworkState(),
    val exportText: String = "",
    val failureMessage: String? = null,
) {
    companion object {
        fun loading(): TeeReport = TeeReport(
            stage = TeeScanStage.LOADING,
            verdict = TeeVerdict.LOADING,
            tier = TeeTier.UNKNOWN,
            headline = "TEE",
            summary = "Collecting local attestation and keystore evidence.",
            collapsedSummary = "Scanning",
            trustRoot = TeeTrustRoot.UNKNOWN,
            trustSummary = "Local trust path pending",
            tamperScore = 0,
            evidenceCount = 0,
            signals = emptyList(),
            sections = emptyList(),
            certificates = emptyList(),
        )

        fun failed(message: String): TeeReport = TeeReport(
            stage = TeeScanStage.FAILED,
            verdict = TeeVerdict.INCONCLUSIVE,
            tier = TeeTier.UNKNOWN,
            headline = "Local TEE verification failed",
            summary = message,
            collapsedSummary = "Scan failed",
            trustRoot = TeeTrustRoot.UNKNOWN,
            trustSummary = "Local trust path unavailable",
            tamperScore = 0,
            evidenceCount = 0,
            signals = emptyList(),
            sections = listOf(
                TeeEvidenceSection(
                    title = "Checks",
                    items = listOf(
                        TeeEvidenceItem(
                            title = "Collection failure",
                            body = message,
                            level = TeeSignalLevel.FAIL,
                        ),
                    ),
                ),
            ),
            certificates = emptyList(),
            failureMessage = message,
        )
    }
}
