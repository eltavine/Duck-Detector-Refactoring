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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeScanStage
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

class TeeReportReducer(
    private val exportFormatter: TeeExportFormatter = TeeExportFormatter(),
) {

    fun reduce(artifacts: TeeScanArtifacts): TeeReport {
        val patchState = buildPatchState(artifacts)
        val policyHardIndicators = collectPolicyHardIndicators(artifacts)
        val policySoftIndicators = collectPolicySoftIndicators(artifacts, patchState)
        val scoredSupplementaryIndicators = collectSupplementaryIndicators(artifacts)
        // A StrongBox routing inconsistency affects review status without adding tamper evidence.
        val supplementaryIndicators =
            scoredSupplementaryIndicators + listOfNotNull(strongBoxAvailabilityIndicator(artifacts))
        val effectiveTier = effectiveTier(artifacts)
        val verdict = determineVerdict(artifacts, policyHardIndicators, policySoftIndicators)
        val supplementaryDangerCount =
            scoredSupplementaryIndicators.count { it.level == TeeSignalLevel.FAIL }
        val supplementaryWarningCount =
            scoredSupplementaryIndicators.count { it.level == TeeSignalLevel.WARN }
        val tamperScore = (
                (policyHardIndicators.size * 28) +
                        (policySoftIndicators.size * 8) +
                        (supplementaryDangerCount * 10) +
                        (supplementaryWarningCount * 4)
                ).coerceAtMost(100)
        val sections = buildSections(
            artifacts = artifacts,
            patchState = patchState,
            policyHardIndicators = policyHardIndicators,
            policySoftIndicators = policySoftIndicators,
            supplementaryIndicators = supplementaryIndicators,
        )
        val normalizedTrustRoot = normalizeTrustRoot(artifacts.trust.trustRoot)
        val nativeProbesAvailable = artifacts.native.collection.isTrustworthy
        val report = TeeReport(
            stage = TeeScanStage.READY,
            verdict = verdict,
            tier = effectiveTier,
            headline = headlineFor(verdict, supplementaryIndicators, nativeProbesAvailable),
            summary = summaryFor(
                verdict = verdict,
                artifacts = artifacts,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
                nativeProbesAvailable = nativeProbesAvailable,
            ),
            collapsedSummary = collapsedSummaryFor(
                verdict = verdict,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
                nativeProbesAvailable = nativeProbesAvailable,
            ),
            trustRoot = normalizedTrustRoot,
            localTrustChainLevel = localTrustChainLevel(artifacts),
            trustSummary = trustSummaryFor(artifacts),
            tamperScore = tamperScore,
            evidenceCount = sections.sumOf { it.items.size },
            supplementaryIndicatorCount = supplementaryIndicators.size,
            supplementaryReviewLevel = supplementaryReviewLevel(supplementaryIndicators),
            nativeProbesAvailable = nativeProbesAvailable,
            signals = buildSignals(
                artifacts = artifacts,
                patchState = patchState,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            ),
            sections = sections,
            certificates = artifacts.snapshot.displayCertificates,
            rkpState = artifacts.rkp,
            patchState = patchState,
            soterState = artifacts.soter,
            networkState = artifacts.crl.networkState,
            exportText = "",
            failureMessage = artifacts.snapshot.errorMessage,
            summaryGrant = summarySourceFor(
                verdict = verdict,
                policyHardIndicators = policyHardIndicators,
                policySoftIndicators = policySoftIndicators,
                supplementaryIndicators = supplementaryIndicators,
            )?.grant,
        )
        return report.copy(exportText = exportFormatter.format(report))
    }
}
