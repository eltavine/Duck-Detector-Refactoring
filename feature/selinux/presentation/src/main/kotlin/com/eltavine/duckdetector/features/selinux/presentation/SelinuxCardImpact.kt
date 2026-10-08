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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.AppZygoteCarrierSupportState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxContextValidityVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxPolicyWeakness
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxSidtabVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import com.eltavine.duckdetector.features.selinux.domain.contextValidityResult
import com.eltavine.duckdetector.features.selinux.domain.contextValiditySupportState
import com.eltavine.duckdetector.features.selinux.domain.firstTrustedPolicyRuleHit
import com.eltavine.duckdetector.features.selinux.domain.policyloadSeqnoResult
import com.eltavine.duckdetector.features.selinux.domain.procAttrCurrentResult
import com.eltavine.duckdetector.features.selinux.domain.sidtabReading
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxImpactItemModel

internal fun buildImpactItems(report: SelinuxReport): List<SelinuxImpactItemModel> {
    val contextValidity = contextValidityResult(report)
    val procAttrCurrent = procAttrCurrentResult(report)
    val policyloadSeqno = policyloadSeqnoResult(report)
    val dirtyPolicyHit = firstTrustedPolicyRuleHit(report)
    val repeatabilityFailed = contextValidity?.contextValidity?.repeatabilityFailed == true
    val appZygoteCarrierState = contextValiditySupportState(contextValidity)
    if (report.stage != SelinuxStage.READY) {
        return when (report.stage) {
            SelinuxStage.LOADING -> listOf(
                SelinuxImpactItemModel(
                    text = "Gathering local status evidence.",
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )

            SelinuxStage.FAILED -> listOf(
                SelinuxImpactItemModel(
                    text = report.errorMessage ?: "Scan failed.",
                    status = DetectorStatus.info(InfoKind.ERROR),
                ),
            )

            SelinuxStage.READY -> emptyList()
        }
    }

    val items = mutableListOf<SelinuxImpactItemModel>()
    when (report.mode) {
        SelinuxMode.ENFORCING -> {
            items += SelinuxImpactItemModel(
                "Mandatory access control is active.",
                DetectorStatus.allClear()
            )
            items += SelinuxImpactItemModel(
                "Policy violations should be blocked and logged.",
                DetectorStatus.allClear()
            )
            if (report.paradoxDetected) {
                items += SelinuxImpactItemModel(
                    "Permission-denied probes acted as positive evidence for enforcing mode.",
                    DetectorStatus.allClear(),
                )
            }
            when (report.auditIntegrity?.state) {
                SelinuxAuditIntegrityState.TAMPERED -> items += SelinuxImpactItemModel(
                    "Audit logs appear rewritten, so SELinux denials may look normal even when privileged contexts are present.",
                    DetectorStatus.danger(),
                )

                SelinuxAuditIntegrityState.EXPOSED -> items += SelinuxImpactItemModel(
                    "Readable SELinux AVC denial lines leaked through the audit surface. This is audit-surface exposure, not direct proof of a root daemon.",
                    DetectorStatus.warning(),
                )

                SelinuxAuditIntegrityState.RESIDUE -> items += SelinuxImpactItemModel(
                    "Readable auditpatch residue suggests audit denials could be relabeled or masked.",
                    DetectorStatus.warning(),
                )

                SelinuxAuditIntegrityState.INCONCLUSIVE -> items += SelinuxImpactItemModel(
                    "Audit rewrite checks were partially unavailable from this app context.",
                    DetectorStatus.info(InfoKind.SUPPORT),
                )

                SelinuxAuditIntegrityState.CLEAR, null -> Unit
            }
            when (report.policyAnalysis?.weakness) {
                SelinuxPolicyWeakness.MODERATE -> items += SelinuxImpactItemModel(
                    "Policy drift may allow some restrictions to be bypassed.",
                    DetectorStatus.warning(),
                )

                SelinuxPolicyWeakness.SEVERE -> items += SelinuxImpactItemModel(
                    "Policy looks heavily weakened, so enforcement may be ineffective.",
                    DetectorStatus.danger(),
                )

                else -> Unit
            }
        }

        SelinuxMode.PERMISSIVE -> {
            items += SelinuxImpactItemModel(
                "Violations are logged but not blocked.",
                DetectorStatus.danger(),
            )
            items += SelinuxImpactItemModel(
                "Security-sensitive apps and integrity checks may fail.",
                DetectorStatus.danger(),
            )
        }

        SelinuxMode.DISABLED -> {
            items += SelinuxImpactItemModel(
                "Mandatory access control is completely disabled.",
                DetectorStatus.danger(),
            )
            items += SelinuxImpactItemModel(
                "Android compatibility requires SELinux in global enforcing mode (CDD 9.7), so this build or boot configuration departs from a compatible one.",
                DetectorStatus.danger(),
            )
        }

        SelinuxMode.UNKNOWN -> {
            items += SelinuxImpactItemModel(
                "Local probes were inconclusive.",
                DetectorStatus.info(InfoKind.ERROR),
            )
        }
    }

    when (contextValidity?.contextValidity?.verdict) {
        SelinuxContextValidityVerdict.KSU_PRESENT -> items += SelinuxImpactItemModel(
            "The app_zygote carrier validated both KSU-specific contexts in live policy.",
            DetectorStatus.danger(),
        )

        SelinuxContextValidityVerdict.CLEAN -> items += SelinuxImpactItemModel(
            "The app_zygote carrier rejected both KSU-specific contexts.",
            DetectorStatus.allClear(),
        )

        SelinuxContextValidityVerdict.SELF_TEST_FAILED -> items += SelinuxImpactItemModel(
            if (repeatabilityFailed) {
                "The context validity oracle repeated inconsistently, so its KSU verdict was not trusted."
            } else {
                "The context validity oracle failed its self-test, so its KSU verdict was not trusted."
            },
            DetectorStatus.warning(),
        )

        SelinuxContextValidityVerdict.AMBIGUOUS -> items += SelinuxImpactItemModel(
            "The context validity oracle split across the two KSU-specific contexts.",
            DetectorStatus.warning(),
        )

        SelinuxContextValidityVerdict.UNSUPPORTED -> items += SelinuxImpactItemModel(
            contextValidity.details ?: "The context validity oracle stayed unavailable.",
            when (appZygoteCarrierState) {
                AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                AppZygoteCarrierSupportState.AVAILABLE -> DetectorStatus.info(InfoKind.SUPPORT)
            },
        )

        else -> Unit
    }
    when {
        policyloadSeqno?.isSecure == false -> items += SelinuxImpactItemModel(
            "The zygotePreload app_zygote carrier observed a policyload/access seqno split.",
            DetectorStatus.danger(),
        )

        policyloadSeqno?.isSecure == true -> items += SelinuxImpactItemModel(
            "The zygotePreload app_zygote carrier reported a coherent policyload/access seqno contract.",
            DetectorStatus.allClear(),
        )

        policyloadSeqno != null -> items += SelinuxImpactItemModel(
            policyloadSeqno.details ?: "The zygotePreload app_zygote seqno oracle stayed unavailable.",
            DetectorStatus.info(InfoKind.SUPPORT),
        )
    }
    when {
        procAttrCurrent?.isSecure == false -> items += SelinuxImpactItemModel(
            "The dedicated app_zygote carrier observed anomalous /proc/self/attr/current writes for ${procAttrCurrent.attrCurrentDetections.joinToString()}.",
            DetectorStatus.danger(),
        )

        procAttrCurrent?.isSecure == true -> items += SelinuxImpactItemModel(
            "The dedicated app_zygote carrier rejected the tested privileged contexts with normal EINVAL results.",
            DetectorStatus.allClear(),
        )

        procAttrCurrent != null -> items += SelinuxImpactItemModel(
            procAttrCurrent.details ?: "The dedicated app_zygote attr/current write probe stayed unavailable.",
            DetectorStatus.info(InfoKind.SUPPORT),
        )
    }
    if (dirtyPolicyHit != null) {
        items += SelinuxImpactItemModel(
            trustedPolicyRuleImpact(dirtyPolicyHit),
            DetectorStatus.warning(),
        )
    }
    if (sidtabReading(report)?.verdict == SelinuxSidtabVerdict.DISCREPANCY_OBSERVED) {
        items += SelinuxImpactItemModel(
            "The app_zygote SID-table experiment twice saw accepted context queries leave the live SID-table count unchanged and rejected attr/current writes increase it. This is supporting evidence, not tool identification or root proof.",
            DetectorStatus.warning(),
        )
    }
    return items
}
