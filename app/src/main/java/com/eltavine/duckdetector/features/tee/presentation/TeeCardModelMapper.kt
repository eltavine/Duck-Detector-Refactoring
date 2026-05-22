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
        TeeVerdict.CONSISTENT -> when {
            // 这些本地信号虽然还挂在 CONSISTENT verdict 之下，但安全语义已经达到红卡级别，所以卡片状态要透传为 danger。
            // These local signals still live under a CONSISTENT verdict, but their security meaning is red-card level, so the card status must escalate to danger.
            hasDangerLocalEscalation() -> DetectorStatus.danger()
            supplementaryIndicatorCount > 0 -> DetectorStatus.warning()
            else -> DetectorStatus.allClear()
        }
        TeeVerdict.SUSPICIOUS -> DetectorStatus.warning()
        TeeVerdict.TAMPERED, TeeVerdict.BROKEN -> DetectorStatus.danger()
        TeeVerdict.INCONCLUSIVE -> DetectorStatus.info(InfoKind.ERROR)
    }

    private fun TeeReport.hasDangerLocalEscalation(): Boolean {
        return sections.asSequence()
            .flatMap { it.items.asSequence() }
            .any { item ->
                // TEE card status is the only value the dashboard aggregates, so red-card local evidence must be recognized from reducer-built Checks rows here.
                // Dashboard 只聚合 TEE card status；因此红卡级本地证据必须在这里从 reducer 生成的 Checks 行识别出来。
                when (item.title) {
                    "Timing side-channel" -> item.level == TeeSignalLevel.FAIL && (
                        item.body.contains("Detected malicious-module fingerprint", ignoreCase = true)
                        )

                    "TEE Simulator generate-mode fingerprint" ->
                        item.level == TeeSignalLevel.FAIL &&
                            item.body.contains("Matched TEE Simulator generate-mode fingerprint.", ignoreCase = true)

                    "ImportKey narrative" ->
                        item.level == TeeSignalLevel.FAIL &&
                            item.body.hasImportKeyRetainedNarrativeDangerKind()

                    "Grant isolated-domain" ->
                        item.level == TeeSignalLevel.FAIL &&
                            item.body.hasGrantIsolatedDomainDangerKind()

                    "Grant self-domain" ->
                        item.level == TeeSignalLevel.FAIL &&
                            item.body.hasGrantSelfDomainDangerKind()

                    else -> false
                }
            }
    }

    private fun String.hasImportKeyRetainedNarrativeDangerKind(): Boolean {
        return contains("kind=IMPORTED_RETAINED_PRIOR_CHAIN", ignoreCase = true) ||
            contains("kind=STALE_GENERATED_AFTER_IMPORT", ignoreCase = true)
    }

    private fun String.hasGrantIsolatedDomainDangerKind(): Boolean {
        // Dashboard only sees TeeCardModel.status, so reducer-level FAIL kinds must be mirrored here deliberately.
        // Dashboard 只看到 TeeCardModel.status，因此 reducer 的 FAIL kind 必须在这里显式镜像。
        return contains("kind=ISOLATED_CHAIN_SPLIT", ignoreCase = true) ||
            contains("kind=ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN", ignoreCase = true)
    }

    private fun String.hasGrantSelfDomainDangerKind(): Boolean {
        // Match stable kind tokens, not prose; prose can change, but these tokens encode the reviewed root cause.
        // 匹配稳定 kind token，而不是自然语言文案；文案可调整，kind 承载已审阅的根因。
        return contains("kind=SELF_CHAIN_SPLIT", ignoreCase = true) ||
            contains("kind=SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN", ignoreCase = true)
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
