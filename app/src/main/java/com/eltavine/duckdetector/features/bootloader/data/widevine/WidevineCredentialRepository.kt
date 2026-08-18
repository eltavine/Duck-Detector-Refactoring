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

package com.eltavine.duckdetector.features.bootloader.data.widevine

import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderImpact
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult

internal data class WidevineBootloaderEvidence(
    val findings: List<BootloaderFinding>,
    val impacts: List<BootloaderImpact>,
    val method: BootloaderMethodResult,
    val anomalyCount: Int,
)

internal class WidevineCredentialRepository(
    private val source: WidevineCredentialSource = WidevineCredentialProbe(),
    private val classifier: WidevineCredentialClassifier = WidevineCredentialClassifier(),
) {

    fun inspect(bootContext: WidevineBootContext): WidevineBootloaderEvidence {
        val snapshot = try {
            source.collect()
        } catch (_: Exception) {
            WidevineCredentialSnapshot()
        }
        val assessment = classifier.classify(snapshot, bootContext)
        return WidevineBootloaderEvidence(
            findings = assessment.findings.map { finding ->
                BootloaderFinding(
                    id = finding.id,
                    label = finding.label,
                    value = finding.value,
                    group = BootloaderFindingGroup.CONSISTENCY,
                    severity = finding.severity.toFindingSeverity(),
                    detail = finding.detail,
                )
            },
            impacts = assessment.impact?.let { impact ->
                listOf(
                    BootloaderImpact(
                        text = impact.detail,
                        severity = impact.severity.toFindingSeverity(),
                    ),
                )
            }.orEmpty(),
            method = BootloaderMethodResult(
                label = "Widevine credential",
                summary = assessment.methodSummary,
                outcome = assessment.methodSeverity.toMethodOutcome(),
                detail = assessment.methodDetail,
            ),
            anomalyCount = assessment.anomalyCount,
        )
    }

    private fun WidevineAssessmentSeverity.toFindingSeverity(): BootloaderFindingSeverity {
        return when (this) {
            WidevineAssessmentSeverity.SAFE -> BootloaderFindingSeverity.SAFE
            WidevineAssessmentSeverity.WARNING -> BootloaderFindingSeverity.WARNING
            WidevineAssessmentSeverity.DANGER -> BootloaderFindingSeverity.DANGER
            WidevineAssessmentSeverity.SUPPORT -> BootloaderFindingSeverity.INFO
        }
    }

    private fun WidevineAssessmentSeverity.toMethodOutcome(): BootloaderMethodOutcome {
        return when (this) {
            WidevineAssessmentSeverity.SAFE -> BootloaderMethodOutcome.CLEAN
            WidevineAssessmentSeverity.WARNING -> BootloaderMethodOutcome.WARNING
            WidevineAssessmentSeverity.DANGER -> BootloaderMethodOutcome.DANGER
            WidevineAssessmentSeverity.SUPPORT -> BootloaderMethodOutcome.SUPPORT
        }
    }
}
