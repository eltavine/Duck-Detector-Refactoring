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

package com.eltavine.duckdetector.features.selinux.domain

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind

fun SelinuxReport.toDetectorStatus(): DetectorStatus {
    val contextValidity = contextValidityResult(this)
    val procAttrCurrent = procAttrCurrentResult(this)
    val policyloadSeqno = policyloadSeqnoResult(this)
    val dirtyPolicyHit = firstTrustedPolicyRuleHit(this)
    val appZygoteCarrierState = contextValiditySupportState(contextValidity)
    return when (stage) {
        SelinuxStage.LOADING -> DetectorStatus.info(InfoKind.SUPPORT)
        SelinuxStage.FAILED -> DetectorStatus.info(InfoKind.ERROR)
        SelinuxStage.READY -> when (mode) {
            SelinuxMode.ENFORCING -> when {
                auditIntegrity?.state == SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
                contextValidity?.contextValidity?.verdict == SelinuxContextValidityVerdict.KSU_PRESENT -> DetectorStatus.danger()
                policyloadSeqno?.isSecure == false -> DetectorStatus.danger()
                procAttrCurrent?.isSecure == false -> DetectorStatus.warning()
                methods.any { it.oracle == SelinuxOracle.ATTR_CURRENT_TIMING && it.isSecure == false } -> DetectorStatus.warning()
                dirtyPolicyHit != null -> DetectorStatus.warning()
                appZygoteCarrierState == AppZygoteCarrierSupportState.UNTRUSTED -> DetectorStatus.warning()
                // After the trusted oracle and carrier checks; before the info-level coverage state, which would mask it.
                sidtabReading(this)?.verdict == SelinuxSidtabVerdict.DISCREPANCY_OBSERVED -> DetectorStatus.warning()
                appZygoteCarrierState == AppZygoteCarrierSupportState.FAILED -> DetectorStatus.info(InfoKind.SUPPORT)
                contextValidity?.contextValidity?.verdict == SelinuxContextValidityVerdict.SELF_TEST_FAILED -> DetectorStatus.warning()
                contextValidity?.contextValidity?.verdict == SelinuxContextValidityVerdict.AMBIGUOUS -> DetectorStatus.warning()
                policyAnalysis?.weakness == SelinuxPolicyWeakness.SEVERE ||
                        policyAnalysis?.weakness == SelinuxPolicyWeakness.MODERATE ||
                        auditIntegrity?.state == SelinuxAuditIntegrityState.EXPOSED ||
                        auditIntegrity?.state == SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()

                else -> DetectorStatus.allClear()
            }

            SelinuxMode.PERMISSIVE, SelinuxMode.DISABLED -> DetectorStatus.danger()
            SelinuxMode.UNKNOWN -> DetectorStatus.info(InfoKind.ERROR)
        }
    }
}

fun contextValidityResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.oracle == SelinuxOracle.CONTEXT_VALIDITY }
}

fun procAttrCurrentResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.oracle == SelinuxOracle.PROC_ATTR_CURRENT_WRITE }
}

fun policyloadSeqnoResult(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull { it.oracle == SelinuxOracle.POLICYLOAD_SEQNO }
}

fun firstTrustedPolicyRuleHit(report: SelinuxReport): SelinuxCheckResult? {
    return report.methods.firstOrNull {
        val rule = it.policyRule
        rule != null &&
            rule.set != SelinuxPolicyRuleSet.POLICY_OBSERVATION &&
            rule.verdict == SelinuxRuleVerdict.ALLOWED &&
            it.isSecure == false &&
            it.dirtyPolicyTrusted
    }
}

fun contextValiditySupportState(result: SelinuxCheckResult?): AppZygoteCarrierSupportState {
    val reading = result?.contextValidity
    return if (reading?.verdict == SelinuxContextValidityVerdict.UNSUPPORTED) {
        reading.carrier
    } else {
        AppZygoteCarrierSupportState.AVAILABLE
    }
}

enum class AppZygoteCarrierSupportState {
    AVAILABLE,
    FAILED,
    UNTRUSTED,
}
