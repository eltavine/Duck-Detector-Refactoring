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

package com.eltavine.duckdetector.features.bootloader.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState
import com.eltavine.duckdetector.features.bootloader.domain.toDetectorStatus
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderCardModel
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderDetailRowModel
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderHeaderFact
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderHeaderFactModel
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderImpactItemModel
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier

class BootloaderCardModelMapper {

    fun map(
        report: BootloaderReport,
    ): BootloaderCardModel {
        return BootloaderCardModel(
            title = "Bootloader",
            subtitle = buildSubtitle(report),
            status = report.toDetectorStatus(),
            assessment = report.toCardAssessment(),
            verdict = buildVerdict(report),
            summary = buildSummary(report),
            headerFacts = buildHeaderFacts(report),
            stateRows = buildRows(report.stage, report.stateRows, statePlaceholders()),
            attestationRows = buildRows(
                report.stage,
                report.attestationRows,
                attestationPlaceholders()
            ),
            propertyRows = buildRows(report.stage, report.propertyRows, propertyPlaceholders()),
            consistencyRows = buildRows(
                report.stage,
                report.consistencyRows,
                consistencyPlaceholders()
            ),
            impactItems = buildImpactItems(report),
            methodRows = buildMethodRows(report),
            scanRows = buildScanRows(report),
        )
    }

    private fun buildSubtitle(report: BootloaderReport): String {
        return when (report.stage) {
            BootloaderStage.LOADING -> "attestation + boot props + DRM consistency"
            BootloaderStage.FAILED -> "local bootloader scan failed"
            BootloaderStage.READY -> "${report.checkedPropertyCount} props · ${report.attestationChainLength} certs · ${report.consistencyFindingCount} cross-checks"
        }
    }

    private fun buildVerdict(report: BootloaderReport): String {
        return when (report.stage) {
            BootloaderStage.LOADING -> "Scanning boot state and verified boot evidence"
            BootloaderStage.FAILED -> "Bootloader scan failed"
            BootloaderStage.READY -> when {
                report.dangerFindings.isNotEmpty() ->
                    "${report.dangerFindings.size} critical boot integrity signal(s)"

                report.warningFindings.isNotEmpty() -> if (report.warningFindings.areWidevineOnly()) {
                    "${report.warningFindings.size} DRM consistency signal(s) need review"
                } else {
                    "${report.warningFindings.size} boot state signal(s) need review"
                }

                report.state == BootloaderState.VERIFIED && report.evidenceMode == BootloaderEvidenceMode.ATTESTATION ->
                    "Locked and attested verified"

                report.state == BootloaderState.VERIFIED -> "Locked by boot properties"
                report.state == BootloaderState.LOCKED_UNKNOWN -> "Locked state without full proof"
                report.state == BootloaderState.UNKNOWN -> "Boot state inconclusive"
                else -> stateLabel(report.state)
            }
        }
    }

    private fun buildSummary(report: BootloaderReport): String {
        return when (report.stage) {
            BootloaderStage.LOADING ->
                "Attestation RootOfTrust, certificate trust, boot properties, raw androidboot parameters, and Widevine credential consistency checks are collecting local evidence."

            BootloaderStage.FAILED ->
                report.errorMessage ?: "Bootloader scan failed before evidence could be assembled."

            BootloaderStage.READY -> when {
                report.dangerFindings.isNotEmpty() ->
                    "Unlocked state, attestation contradictions, broken certificate trust, or verified-boot failures indicate reduced device trust."

                report.warningFindings.isNotEmpty() ->
                    "The boot chain is not obviously broken, but custom-root, software-only, Widevine DRM, or cross-source coherence signals still need review."

                report.evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY ->
                    "Boot properties look conservative, but the result falls back to software-readable signals because attestation RootOfTrust was unavailable."

                report.evidenceMode == BootloaderEvidenceMode.UNAVAILABLE ->
                    "Neither attestation RootOfTrust nor readable boot properties exposed enough data for a confident bootloader verdict."

                else ->
                    "No unlock or integrity contradiction was observed in the available boot evidence. Individual checks show comparison coverage."
            }
        }
    }

    private fun buildHeaderFacts(report: BootloaderReport): List<BootloaderHeaderFactModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> placeholderFacts(
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
            BootloaderStage.READY -> listOf(
                BootloaderHeaderFactModel(
                    fact = BootloaderHeaderFact.STATE,
                    value = stateLabel(report.state),
                    status = report.authoritativeStateStatus(),
                ),
                BootloaderHeaderFactModel(
                    fact = BootloaderHeaderFact.PROOF,
                    value = proofLabel(report.evidenceMode),
                    status = when (report.evidenceMode) {
                        BootloaderEvidenceMode.ATTESTATION -> DetectorStatus.allClear()
                        BootloaderEvidenceMode.PROPERTIES_ONLY -> DetectorStatus.info(InfoKind.SUPPORT)
                        BootloaderEvidenceMode.UNAVAILABLE -> DetectorStatus.warning()
                    },
                ),
                BootloaderHeaderFactModel(
                    fact = BootloaderHeaderFact.TIER,
                    value = tierLabel(report.tier),
                    status = when (report.tier) {
                        TeeTier.STRONGBOX,
                        TeeTier.TEE -> DetectorStatus.allClear()

                        TeeTier.SOFTWARE -> DetectorStatus.warning()
                        TeeTier.NONE,
                        TeeTier.UNKNOWN -> DetectorStatus.info(InfoKind.SUPPORT)
                    },
                ),
                BootloaderHeaderFactModel(
                    fact = BootloaderHeaderFact.TRUST,
                    value = trustLabel(report.trustRoot),
                    status = trustStatus(report),
                ),
            )
        }
    }

    private fun buildRows(
        stage: BootloaderStage,
        rows: List<BootloaderFinding>,
        placeholders: List<String>,
    ): List<BootloaderDetailRowModel> {
        return when (stage) {
            BootloaderStage.LOADING -> placeholderRows(
                placeholders,
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderRows(
                placeholders,
                "Error",
                DetectorStatus.info(InfoKind.ERROR)
            )

            BootloaderStage.READY -> if (rows.isEmpty()) {
                listOf(
                    BootloaderDetailRowModel(
                        label = "Status",
                        value = "None",
                        status = DetectorStatus.info(InfoKind.SUPPORT),
                        detail = "No rows were produced for this section on this device.",
                    ),
                )
            } else {
                rows.map(::findingRow)
            }
        }
    }

    private fun buildImpactItems(report: BootloaderReport): List<BootloaderImpactItemModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> listOf(
                BootloaderImpactItemModel(
                    text = "Gathering attestation, verified-boot, and property consistency evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            BootloaderStage.FAILED -> listOf(
                BootloaderImpactItemModel(
                    text = report.errorMessage ?: "Bootloader scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            BootloaderStage.READY -> report.impacts.map { impact ->
                BootloaderImpactItemModel(
                    text = impact.text,
                    status = severityStatus(impact.severity),
                )
            }
        }
    }

    private fun buildMethodRows(report: BootloaderReport): List<BootloaderDetailRowModel> {
        return when (report.stage) {
            BootloaderStage.LOADING -> placeholderRows(
                methodPlaceholders(),
                "Pending",
                DetectorStatus.info(InfoKind.SUPPORT)
            )

            BootloaderStage.FAILED -> placeholderRows(
                methodPlaceholders(),
                "Failed",
                DetectorStatus.info(InfoKind.ERROR)
            )

            BootloaderStage.READY -> report.methods.map { result ->
                BootloaderDetailRowModel(
                    label = result.label,
                    value = result.summary,
                    status = methodStatus(result),
                    detail = result.detail,
                    detailMonospace = true,
                )
            }
        }
    }

    private fun findingRow(finding: BootloaderFinding): BootloaderDetailRowModel {
        return BootloaderDetailRowModel(
            label = finding.label,
            value = badgeValue(finding.value),
            status = severityStatus(finding.severity),
            detail = finding.detail,
            detailMonospace = finding.detailMonospace,
        )
    }

    private fun placeholderFacts(
        value: String,
        status: DetectorStatus
    ): List<BootloaderHeaderFactModel> {
        return listOf(
            BootloaderHeaderFactModel(BootloaderHeaderFact.STATE, value, status),
            BootloaderHeaderFactModel(BootloaderHeaderFact.PROOF, value, status),
            BootloaderHeaderFactModel(BootloaderHeaderFact.TIER, value, status),
            BootloaderHeaderFactModel(BootloaderHeaderFact.TRUST, value, status),
        )
    }

    private fun statePlaceholders(): List<String> =
        listOf("Boot state", "Evidence source", "Lock state", "Trust root")

    private fun attestationPlaceholders(): List<String> = listOf(
        "Attestation tier",
        "Certificate chain",
        "Attested boot state",
        "Attested deviceLocked"
    )

    private fun propertyPlaceholders(): List<String> = listOf(
        "ro.boot.flash.locked",
        "ro.boot.verifiedbootstate",
        "ro.boot.vbmeta.device_state",
        "partition.system.verified"
    )

    private fun consistencyPlaceholders(): List<String> = listOf(
        "Attested hash vs vbmeta digest",
        "Verified boot coherence",
        "Property source mismatch",
        "Widevine credential",
        "Widevine Java/native parity",
    )

    private fun methodPlaceholders(): List<String> = listOf(
        "Key attestation",
        "Certificate trust",
        "Boot consistency",
        "Property catalog",
        "Reflection API",
        "getprop snapshot",
        "Native libc",
        "Raw boot params",
        "Source consistency",
        "Cross-check rules",
        "Widevine credential",
    )

    private fun List<BootloaderFinding>.areWidevineOnly(): Boolean {
        return isNotEmpty() && all { finding -> finding.id.startsWith(WIDEVINE_FINDING_PREFIX) }
    }

    private fun severityStatus(severity: BootloaderFindingSeverity): DetectorStatus {
        return when (severity) {
            BootloaderFindingSeverity.SAFE -> DetectorStatus.allClear()
            BootloaderFindingSeverity.WARNING -> DetectorStatus.warning()
            BootloaderFindingSeverity.DANGER -> DetectorStatus.danger()
            BootloaderFindingSeverity.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun methodStatus(result: BootloaderMethodResult): DetectorStatus {
        return when (result.outcome) {
            BootloaderMethodOutcome.CLEAN -> DetectorStatus.allClear()
            BootloaderMethodOutcome.WARNING -> DetectorStatus.warning()
            BootloaderMethodOutcome.DANGER -> DetectorStatus.danger()
            BootloaderMethodOutcome.SUPPORT -> DetectorStatus.info(InfoKind.SUPPORT)
        }
    }

    private fun badgeValue(value: String): String {
        return if (value.length > 18) value.take(17) + "…" else value
    }

}
