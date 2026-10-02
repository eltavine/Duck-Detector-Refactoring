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

import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.GrantSelfDomainAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SyntheticGrantGranteeBlindReadbackAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionAnomalyKind
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerAnomalyKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceTopic
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun collectSupplementaryIndicators(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> {
    return buildList {
        addEnvironmentAndGrantIndicators(artifacts)
        addKeystoreIndicators(artifacts)
        addKeyMaterialAndBinderIndicators(artifacts)
        addNativeAndStrongBoxIndicators(artifacts)
    }
}

private fun MutableList<TeeEvidenceItem>.addEnvironmentAndGrantIndicators(artifacts: TeeScanArtifacts) {
    if (artifacts.soter.abnormalEnvironment) {
        add(
            fact(
                "Soter environment",
                artifacts.soter.summary,
                TeeSignalLevel.WARN,
                topic = TeeEvidenceTopic.SOTER,
            )
        )
    }
    if (artifacts.soter.anomalies.isNotEmpty()) {
        add(
            fact(
                "Soter abuse evidence",
                artifacts.soter.anomalies.joinToString(separator = "; ") { it.detail },
                TeeSignalLevel.WARN,
                topic = TeeEvidenceTopic.SOTER,
            )
        )
    }
    val timingSideChannelSkipSignature = timingSideChannelSkipSignature(artifacts.timingSideChannel)
    if (timingSideChannelSkipSignature != null) {
        add(
            fact(
                "Timing side-channel",
                timingSideChannelSkipSignature.summary,
                timingSideChannelSkipSignature.level,
            )
        )
    } else if (
        artifacts.timingSideChannel.measurementAvailable &&
        artifacts.timingSideChannel.ratioEligible &&
        artifacts.timingSideChannel.suspicious
    ) {
        add(
            fact(
                "Timing side-channel",
                timingSideChannelSummary(artifacts),
                TeeSignalLevel.WARN,
            )
        )
    }
    val generateModeLevel = generateModeAnomalyLevel(artifacts)
    if (generateModeLevel == TeeSignalLevel.FAIL || generateModeLevel == TeeSignalLevel.WARN) {
        add(
            fact(
                "TEE Simulator generate-mode fingerprint",
                generateModeAnomalyValue(artifacts),
                generateModeLevel,
                hiddenCopyText = artifacts.generateModeParcelFingerprint.diagnosticCopyText,
            )
        )
    }
    if (artifacts.vintfKeyMintVersion.anomalyKind == VintfKeyMintVersionAnomalyKind.MISMATCH) {
        // This is reported separately from the crypto capability row. A version/tier
        // identity mismatch means the target backend cannot be selected unambiguously;
        // it is evidence about identity, not evidence that an MGF1 operation executed.
        // 这里必须与 crypto capability 分开报告。版本/tier 身份冲突表示无法唯一选中
        // backend，它是“身份不一致”证据，不是“MGF1 已执行且失败”证据。
        val runtimeIdentityMismatch = keyMintRuntimeIdentityMismatch(artifacts)
        add(
            fact(
                if (runtimeIdentityMismatch) "KeyMint runtime identity" else "KeyMint VINTF",
                if (runtimeIdentityMismatch) {
                    "Attestation and keymaster versions violate the AOSP single-runtime mapping. " +
                        vintfKeyMintVersionValue(artifacts)
                } else {
                    "VINTF KeyMint version diverged from attestation. " +
                        vintfKeyMintVersionValue(artifacts)
                },
                TeeSignalLevel.FAIL,
                hiddenCopyText = artifacts.vintfKeyMintVersion.diagnosticCopyText,
            )
        )
    }
    // ATTEST_KEY 路径在 security_level.rs 里没有后处理调用点，所以这两类都是强本地证据：
    // RootOfTrust 在两条分支间分叉，或 RKP 路径的单侧延迟显著超过本机噪声
    // The ATTEST_KEY path has no post-processing call site in security_level.rs, so both of these are strong
    // local evidence: RootOfTrust forking between the arms, or one-sided RKP-path latency well above this
    // device's own noise.
    if (
        artifacts.postProcessing.anomalyKind ==
            Keystore2PostProcessingAnomalyKind.ROOT_OF_TRUST_DIVERGENCE ||
        artifacts.postProcessing.anomalyKind ==
            Keystore2PostProcessingAnomalyKind.TIMING_DETECTED
    ) {
        add(
            fact(
                "Cert post-processing",
                postProcessingValue(artifacts),
                TeeSignalLevel.FAIL,
            )
        )
    }
    if (
        artifacts.rkpProvisionedManufacturer.anomalyKind ==
            RkpProvisionedManufacturerAnomalyKind.MISMATCH
    ) {
        add(
            fact(
                "RKP manufacturer",
                rkpProvisionedManufacturerValue(artifacts),
                TeeSignalLevel.FAIL,
            )
        )
    }
    // Grant checks are supplementary, but these two kinds are strong local evidence:
    // Grant 检测属于补充证据；但下面两类是强本地证据：
    // 1) chain split means owner alias and Domain.GRANT return different ordered certificate narratives.
    // 1) chain split 表示 owner alias 与 Domain.GRANT 返回了不同的有序证书叙事。
    // 2) key-not-found after owner chain means the alias exists in owner view but not in grant lookup.
    // 2) owner chain 后 key-not-found 表示 alias 存在于 owner 视图，却不存在于 grant 查找路径。
    when (artifacts.grantDomainFullChainSplit.anomalyKind) {
        GrantDomainAnomalyKind.ISOLATED_CHAIN_SPLIT -> {
            add(
                fact(
                    "Grant isolated-domain",
                    "Grant isolated-domain certificate-chain narrative split detected. " +
                        grantDomainFullChainSplitValue(artifacts),
                    TeeSignalLevel.FAIL,
                    hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                        .takeIf { it.isNotBlank() },
                    grant = isolatedDomainGrantEvidence(artifacts),
                )
            )
        }

        GrantDomainAnomalyKind.ISOLATED_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN -> {
            add(
                fact(
                    "Grant isolated-domain",
                    "Grant isolated-domain key visibility divergence detected. " +
                        grantDomainFullChainSplitValue(artifacts),
                    TeeSignalLevel.FAIL,
                    hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                        .takeIf { it.isNotBlank() },
                    grant = isolatedDomainGrantEvidence(artifacts, sentenceNamesKeyVisibility = true),
                )
            )
        }

        GrantDomainAnomalyKind.ISOLATED_PRIVATE_READBACK_CRASH -> {
            add(
                fact(
                    "Grant isolated-domain",
                    "Grant isolated-domain isolated private readback crashed after grant succeeded. " +
                        grantDomainFullChainSplitValue(artifacts),
                    TeeSignalLevel.WARN,
                    hiddenCopyText = artifacts.grantDomainFullChainSplit.diagnosticCopyText
                        .takeIf { it.isNotBlank() },
                    grant = isolatedDomainGrantEvidence(artifacts),
                )
            )
        }

        GrantDomainAnomalyKind.NONE,
        GrantDomainAnomalyKind.UNAVAILABLE -> Unit
    }
    if (
        artifacts.syntheticGrantGranteeBlindReadback.anomalyKind ==
        SyntheticGrantGranteeBlindReadbackAnomalyKind.NON_GRANTEE_READBACK_ALLOWED
    ) {
        add(
            fact(
                "Grant caller binding",
                "Grant handle remained readable by its non-grantee owner. " +
                    syntheticGrantGranteeBlindReadbackValue(artifacts),
                TeeSignalLevel.FAIL,
                hiddenCopyText = artifacts.syntheticGrantGranteeBlindReadback.diagnosticCopyText
                    .takeIf { it.isNotBlank() },
                grant = callerBindingGrantEvidence(artifacts),
            )
        )
    }
    if (
        artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness.anomalyKind ==
        SyntheticGrantGetKeyEntryAccessVectorBlindnessAnomalyKind.GET_KEY_ENTRY_WITHOUT_GET_INFO_ALLOWED
    ) {
        add(
            fact(
                "Grant access vector",
                "Domain.GRANT handle without GET_INFO still allowed getKeyEntry metadata readback. " +
                    syntheticGrantGetKeyEntryAccessVectorBlindnessValue(artifacts),
                TeeSignalLevel.FAIL,
                hiddenCopyText = artifacts.syntheticGrantGetKeyEntryAccessVectorBlindness.diagnosticCopyText
                    .takeIf { it.isNotBlank() },
            )
        )
    }
    // self-domain removes the isolated-process policy variable; its key-not-found variant is treated like a visibility split.
    // self-domain 排除了 isolated-process 策略变量；其 key-not-found 变体按可见性断裂处理。
    when (artifacts.grantSelfDomainFullChainSplit.anomalyKind) {
        GrantSelfDomainAnomalyKind.SELF_CHAIN_SPLIT -> {
            add(
                fact(
                    "Grant self-domain",
                    "Grant self-domain certificate-chain split detected. " +
                        grantSelfDomainFullChainSplitValue(artifacts),
                    TeeSignalLevel.FAIL,
                    hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                        .takeIf { it.isNotBlank() },
                    grant = selfDomainGrantEvidence(artifacts),
                )
            )
        }

        GrantSelfDomainAnomalyKind.SELF_GRANT_KEY_NOT_FOUND_AFTER_OWNER_CHAIN -> {
            add(
                fact(
                    "Grant self-domain",
                    "Grant self-domain key visibility divergence detected. " +
                        grantSelfDomainFullChainSplitValue(artifacts),
                    TeeSignalLevel.FAIL,
                    hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                        .takeIf { it.isNotBlank() },
                    grant = selfDomainGrantEvidence(artifacts, sentenceNamesKeyVisibility = true),
                )
            )
        }

        GrantSelfDomainAnomalyKind.SELF_GRANT_ATTESTATION_APP_KEY_NOT_FOUND -> {
            add(
                fact(
                    "Grant self-domain",
                    "Grant self-domain custom-attestation visibility divergence detected. " +
                        grantSelfDomainFullChainSplitValue(artifacts),
                    TeeSignalLevel.FAIL,
                    hiddenCopyText = artifacts.grantSelfDomainFullChainSplit.diagnosticCopyText
                        .takeIf { it.isNotBlank() },
                    grant = selfDomainGrantEvidence(artifacts),
                )
            )
        }

        GrantSelfDomainAnomalyKind.NONE,
        GrantSelfDomainAnomalyKind.UNAVAILABLE -> Unit
    }
}
