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

package com.eltavine.duckdetector.features.tee.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import com.eltavine.duckdetector.features.tee.domain.TeeVerdict
import com.eltavine.duckdetector.features.tee.ui.model.TeeCardModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeCertificateSummaryModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeFactGroupModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeFactIcon
import com.eltavine.duckdetector.features.tee.ui.model.TeeFactRowModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionId
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeHeaderFactModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeHighlightSignalModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeNetworkStateModel

class TeeCardModelMapper {

    fun map(
        report: TeeReport,
        isExpanded: Boolean,
    ): TeeCardModel {
        val status = report.toDetectorStatus()
        return TeeCardModel(
            title = "TEE",
            subtitle = report.trustSummary,
            status = status,
            verdict = report.headline,
            summary = report.summary,
            findingDetail = report.topFindingDetail(),
            rkpBadgeLabel = rkpBadgeLabel(report),
            isExpanded = isExpanded,
            headerFacts = buildHeaderFacts(report, status),
            highlightSignals = report.signals.take(4).map { signal ->
                TeeHighlightSignalModel(
                    label = signal.label,
                    value = signal.value,
                    status = signal.level.toDetectorStatus(),
                )
            },
            factGroups = report.sections.map { section ->
                TeeFactGroupModel(
                    title = section.title,
                    rows = section.items.map { item ->
                        TeeFactRowModel(
                            icon = iconFor(section.title, item.title),
                            label = item.title,
                            value = item.body,
                            status = item.level.toDetectorStatus(),
                            hiddenCopyText = item.hiddenCopyText,
                        )
                    },
                )
            },
            certificateSummary = TeeCertificateSummaryModel(
                label = "Certificate chain",
                count = report.certificates.size.toString(),
                certificates = report.certificates,
            ),
            actions = buildActions(report),
            networkState = TeeNetworkStateModel(
                label = "Network",
                summary = report.networkState.summary,
                status = when (report.networkState.mode) {
                    TeeNetworkMode.ACTIVE -> DetectorStatus.allClear()
                    TeeNetworkMode.CONSENT_REQUIRED -> DetectorStatus.info(InfoKind.SUPPORT)
                    TeeNetworkMode.ERROR -> DetectorStatus.info(InfoKind.ERROR)
                    TeeNetworkMode.SKIPPED -> DetectorStatus.info(InfoKind.SUPPORT)
                    TeeNetworkMode.INACTIVE -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            exportText = report.exportText,
        )
    }

    private fun buildHeaderFacts(
        report: TeeReport,
        status: DetectorStatus,
    ): List<TeeHeaderFactModel> {
        val scoreStatus = if (report.tamperScore > 0) {
            when {
                report.tamperScore >= 60 -> DetectorStatus.danger()
                report.tamperScore >= 24 -> DetectorStatus.warning()
                else -> DetectorStatus.allClear()
            }
        } else {
            DetectorStatus.allClear()
        }
        return listOf(
            TeeHeaderFactModel("Verdict", verdictValue(report), status),
            TeeHeaderFactModel("Tier", report.tier.displayName(), report.tierStatus()),
            TeeHeaderFactModel("Trust", trustRootValue(report), report.trustStatus()),
            TeeHeaderFactModel("Score", report.tamperScore.toString(), scoreStatus),
        )
    }

    private fun buildActions(report: TeeReport): List<TeeFooterActionModel> {
        val actions = mutableListOf(
            TeeFooterActionModel(TeeFooterActionId.DETAILS, "Details"),
        )
        if (report.certificates.isNotEmpty()) {
            actions += TeeFooterActionModel(
                id = TeeFooterActionId.CERTIFICATES,
                label = "Certificates",
                counter = report.certificates.size.toString(),
            )
        }
        return actions
    }

    private fun verdictValue(report: TeeReport): String = when (report.verdict) {
        TeeVerdict.LOADING -> "Scanning"
        TeeVerdict.CONSISTENT -> if (report.supplementaryIndicatorCount > 0) {
            "Aligned + review"
        } else {
            "Aligned"
        }
        TeeVerdict.SUSPICIOUS -> "Review"
        TeeVerdict.TAMPERED -> "Tampered"
        TeeVerdict.BROKEN -> "Broken"
        TeeVerdict.INCONCLUSIVE -> "Mixed"
    }

    private fun rkpBadgeLabel(report: TeeReport): String? =
        if (report.rkpState.provisioned && report.localTrustChainLevel == TeeSignalLevel.PASS) {
            "RKP"
        } else {
            null
        }

    private fun TeeReport.topFindingDetail(): String? {
        if (
            !summary.contains("Grant self-domain") &&
            !summary.contains("Grant isolated-domain") &&
            !summary.contains("Grant handle")
        ) {
            return null
        }
        // Grant stage details can include Java/hidden/private summaries. Keep that audit text inside
        // the TEE card; Dashboard top findings should be a short routing hint, not a diagnostic dump.
        // Grant 阶段细节可能包含 Java/hidden/private 摘要。审计文本留在 TEE 卡片内；Dashboard 顶层 finding 只给短路由提示，不承载诊断 dump。
        val grantFailure = sections
            .asSequence()
            .flatMap { section -> section.items.asSequence() }
            .firstOrNull { item ->
                item.level == TeeSignalLevel.FAIL &&
                    (
                        item.title == "Grant self-domain" ||
                            item.title == "Grant isolated-domain" ||
                            item.title == "Grant caller binding"
                        )
            }
            ?: sections
                .asSequence()
                .flatMap { section -> section.items.asSequence() }
                .firstOrNull { item ->
                    item.level == TeeSignalLevel.WARN &&
                        (
                            item.title == "Grant self-domain" ||
                                item.title == "Grant isolated-domain" ||
                                item.title == "Grant caller binding"
                            )
                }
                ?: return null

        val keyVisibilityDiverged =
            summary.contains("key visibility", ignoreCase = true) ||
                grantFailure.body.contains("key visibility", ignoreCase = true) ||
                grantFailure.body.contains("KEY_NOT_FOUND", ignoreCase = true)
        return when (grantFailure.title) {
            "Grant self-domain" -> if (keyVisibilityDiverged) {
                "Grant self-domain key visibility diverged; open TEE details for stage diagnostics."
            } else {
                "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics."
            }
            "Grant isolated-domain" -> if (keyVisibilityDiverged) {
                "Grant isolated-domain key visibility diverged; open TEE details for stage diagnostics."
            } else if (grantFailure.level == TeeSignalLevel.WARN) {
                "Grant isolated-domain runtime crash; open TEE details for stage diagnostics."
            } else {
                "Grant isolated-domain certificate chain diverged; open TEE details for stage diagnostics."
            }
            "Grant caller binding" ->
                "Grant handle caller binding failed; open TEE details for stage diagnostics."
            else -> null
        }
    }

    private fun trustRootValue(report: TeeReport): String = when (report.trustRoot) {
        TeeTrustRoot.GOOGLE_RKP -> "Google"
        TeeTrustRoot.GOOGLE -> "Google"
        TeeTrustRoot.AOSP -> "AOSP"
        TeeTrustRoot.FACTORY -> "Factory"
        TeeTrustRoot.UNKNOWN -> "Unknown"
    }

    private fun iconFor(
        sectionTitle: String,
        itemTitle: String,
    ): TeeFactIcon {
        return when (sectionTitle) {
            "Trust" -> when (itemTitle) {
                "Trust root" -> TeeFactIcon.TRUST
                "RKP" -> TeeFactIcon.RKP
                "CRL" -> TeeFactIcon.NETWORK
                "Root fingerprint" -> TeeFactIcon.CERTIFICATE
                else -> TeeFactIcon.CERTIFICATE
            }

            "Attestation" -> when (itemTitle) {
                "Verified boot" -> TeeFactIcon.BOOT
                "Boot consistency" -> TeeFactIcon.BOOT
                "Patch levels" -> TeeFactIcon.PATCH
                "Device IDs" -> TeeFactIcon.DEVICE
                "Key properties" -> TeeFactIcon.KEY
                "User auth" -> TeeFactIcon.AUTH
                "Application" -> TeeFactIcon.APP
                else -> TeeFactIcon.KEY
            }

            "Checks" -> when (itemTitle) {
                "Timing" -> TeeFactIcon.TIMING
                "StrongBox" -> TeeFactIcon.STRONGBOX
                "Native" -> TeeFactIcon.NATIVE
                "Soter" -> TeeFactIcon.SOTER
                "Indicators" -> TeeFactIcon.WARNING
                else -> TeeFactIcon.KEYSTORE
            }

            else -> TeeFactIcon.WARNING
        }
    }

    private fun TeeReport.toDetectorStatus(): DetectorStatus = when (verdict) {
        TeeVerdict.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        TeeVerdict.CONSISTENT,
        TeeVerdict.SUSPICIOUS -> when {
            // Dashboard aggregates only TeeCardModel.status; consume reducer structure, not prose or row titles.
            // Dashboard 只聚合 TeeCardModel.status；这里消费 reducer 的结构化级别，不解析文案或行标题。
            supplementaryReviewLevel == TeeSignalLevel.FAIL -> DetectorStatus.danger()
            supplementaryReviewLevel == TeeSignalLevel.WARN -> DetectorStatus.warning()
            verdict == TeeVerdict.SUSPICIOUS -> DetectorStatus.warning()
            supplementaryIndicatorCount > 0 -> DetectorStatus.warning()
            else -> DetectorStatus.allClear()
        }
        TeeVerdict.TAMPERED, TeeVerdict.BROKEN -> DetectorStatus.danger()
        TeeVerdict.INCONCLUSIVE -> DetectorStatus.info(InfoKind.ERROR)
    }

    private fun TeeReport.tierStatus(): DetectorStatus = when (tier) {
        com.eltavine.duckdetector.features.tee.domain.TeeTier.STRONGBOX,
        com.eltavine.duckdetector.features.tee.domain.TeeTier.TEE -> DetectorStatus.allClear()

        com.eltavine.duckdetector.features.tee.domain.TeeTier.SOFTWARE -> DetectorStatus.warning()
        com.eltavine.duckdetector.features.tee.domain.TeeTier.NONE -> DetectorStatus.danger()
        com.eltavine.duckdetector.features.tee.domain.TeeTier.UNKNOWN -> DetectorStatus.info(
            InfoKind.SUPPORT
        )
    }

    private fun TeeReport.trustStatus(): DetectorStatus = when {
        localTrustChainLevel == TeeSignalLevel.FAIL -> DetectorStatus.danger()
        localTrustChainLevel == TeeSignalLevel.WARN -> DetectorStatus.warning()
        trustRoot == TeeTrustRoot.GOOGLE || trustRoot == TeeTrustRoot.GOOGLE_RKP -> DetectorStatus.allClear()
        trustRoot == TeeTrustRoot.AOSP -> DetectorStatus.warning()
        else -> DetectorStatus.info(InfoKind.SUPPORT)
    }

    private fun TeeSignalLevel.toDetectorStatus(): DetectorStatus = when (this) {
        TeeSignalLevel.PASS -> DetectorStatus.allClear()
        TeeSignalLevel.INFO -> DetectorStatus.info(InfoKind.SUPPORT)
        TeeSignalLevel.WARN -> DetectorStatus.warning()
        TeeSignalLevel.FAIL -> DetectorStatus.danger()
    }

    private fun com.eltavine.duckdetector.features.tee.domain.TeeTier.displayName(): String =
        when (this) {
            com.eltavine.duckdetector.features.tee.domain.TeeTier.UNKNOWN -> "Unknown"
            com.eltavine.duckdetector.features.tee.domain.TeeTier.NONE -> "None"
            com.eltavine.duckdetector.features.tee.domain.TeeTier.SOFTWARE -> "Software"
            com.eltavine.duckdetector.features.tee.domain.TeeTier.TEE -> "TEE"
            com.eltavine.duckdetector.features.tee.domain.TeeTier.STRONGBOX -> "StrongBox"
        }
}
