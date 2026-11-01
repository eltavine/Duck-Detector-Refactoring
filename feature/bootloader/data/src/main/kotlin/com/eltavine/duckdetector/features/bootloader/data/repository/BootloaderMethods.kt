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

package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustResult
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.capability.attestation.domain.TeeTrustRoot
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.bootloader.data.rules.BootloaderCatalog
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineBootloaderEvidence
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderImpact
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState

internal fun buildMethods(
    evidenceMode: BootloaderEvidenceMode,
    attestation: AttestationSnapshot,
    trust: CertificateTrustResult,
    bootConsistency: BootConsistencyResult,
    nativeSnapshot: SystemPropertiesNativeSnapshot,
    observedPropertyCount: Int,
    reflectionHitCount: Int,
    getpropHitCount: Int,
    sourceSignals: List<SystemPropertySignal>,
    consistencySignals: List<SystemPropertySignal>,
    propertyContext: BootloaderPropertyContext,
    widevineEvidence: WidevineBootloaderEvidence,
): List<BootloaderMethodResult> {
    return listOf(
        BootloaderMethodResult(
            label = "Key attestation",
            summary = when {
                hasAttestation(attestation) -> tierLabel(attestation.tier)
                BootloaderSeverityRules.isKeyPairGenerationFailure(attestation.errorMessage) ->
                    "Failed"

                evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY -> "Fallback only"
                else -> "Unavailable"
            },
            outcome = when {
                hasAttestation(attestation) && (attestation.tier == TeeTier.TEE || attestation.tier == TeeTier.STRONGBOX) ->
                    BootloaderMethodOutcome.CLEAN

                hasAttestation(attestation) -> BootloaderMethodOutcome.WARNING
                BootloaderSeverityRules.isKeyPairGenerationFailure(attestation.errorMessage) ->
                    BootloaderMethodOutcome.DANGER

                evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY -> BootloaderMethodOutcome.SUPPORT
                else -> BootloaderMethodOutcome.SUPPORT
            },
            detail = attestation.errorMessage
                ?: "RootOfTrust availability: ${attestation.rootOfTrust != null}.",
        ),
        BootloaderMethodResult(
            label = "Certificate trust",
            summary = when {
                trust.chainLength == 0 -> "No chain"
                !trust.chainSignatureValid -> "Invalid"
                else -> trustRootLabel(trust.trustRoot)
            },
            outcome = when {
                trust.chainLength == 0 -> BootloaderMethodOutcome.DANGER
                !trust.chainSignatureValid || trust.expiredCertificates.isNotEmpty() || trust.issuerMismatches.isNotEmpty() ->
                    BootloaderMethodOutcome.DANGER

                trust.trustRoot == TeeTrustRoot.UNKNOWN -> BootloaderMethodOutcome.DANGER
                trust.trustRoot == TeeTrustRoot.AOSP -> BootloaderMethodOutcome.WARNING
                else -> BootloaderMethodOutcome.CLEAN
            },
            detail = buildChainDetail(trust),
        ),
        BootloaderMethodResult(
            label = "Boot consistency",
            summary = when {
                bootConsistency.hasHardAnomaly -> "Anomaly"
                bootConsistency.runtimeComparisonPerformed -> "Aligned"
                else -> "Not compared"
            },
            outcome = when {
                bootConsistency.hasHardAnomaly -> BootloaderMethodOutcome.DANGER
                bootConsistency.runtimeComparisonPerformed -> BootloaderMethodOutcome.CLEAN
                else -> BootloaderMethodOutcome.SUPPORT
            },
            detail = bootConsistency.detail,
        ),
        BootloaderMethodResult(
            label = "Property catalog",
            summary = "$observedPropertyCount / ${BootloaderCatalog.properties.size} observed",
            outcome = when {
                observedPropertyCount == 0 -> BootloaderMethodOutcome.SUPPORT
                propertyContext.hasDangerProperty -> BootloaderMethodOutcome.DANGER
                propertyContext.hasWarningProperty -> BootloaderMethodOutcome.WARNING
                else -> BootloaderMethodOutcome.CLEAN
            },
            detail = "Tracked boot, AVB, dm-verity, Samsung fuse, and secure-build properties.",
        ),
        BootloaderMethodResult(
            label = "Reflection API",
            summary = if (reflectionHitCount > 0) "$reflectionHitCount hit(s)" else "Unavailable",
            outcome = if (reflectionHitCount > 0) BootloaderMethodOutcome.CLEAN else BootloaderMethodOutcome.SUPPORT,
            detail = "android.os.SystemProperties reflection reads for tracked boot properties.",
        ),
        BootloaderMethodResult(
            label = "getprop snapshot",
            summary = if (getpropHitCount > 0) "$getpropHitCount hit(s)" else "Unavailable",
            outcome = if (getpropHitCount > 0) BootloaderMethodOutcome.CLEAN else BootloaderMethodOutcome.SUPPORT,
            detail = "Single getprop dump reused for cross-source comparisons.",
        ),
        BootloaderMethodResult(
            label = "Native libc",
            summary = if (nativeSnapshot.nativePropertyHitCount > 0) {
                "${nativeSnapshot.nativePropertyHitCount} hit(s)"
            } else {
                "Unavailable"
            },
            outcome = if (nativeSnapshot.nativePropertyHitCount > 0) {
                BootloaderMethodOutcome.CLEAN
            } else {
                BootloaderMethodOutcome.SUPPORT
            },
            detail = "Native libc property cross-checks using the callback-based system property API.",
        ),
        BootloaderMethodResult(
            label = "Raw boot params",
            summary = if (nativeSnapshot.bootParamHitCount > 0) {
                "${nativeSnapshot.bootParamHitCount} hit(s)"
            } else {
                "Unavailable"
            },
            outcome = if (nativeSnapshot.bootParamHitCount > 0) {
                BootloaderMethodOutcome.CLEAN
            } else {
                BootloaderMethodOutcome.SUPPORT
            },
            detail = "androidboot.* values from /proc/cmdline and /proc/bootconfig.",
        ),
        BootloaderMethodResult(
            label = "Source consistency",
            summary = if (sourceSignals.isEmpty()) "Aligned" else "${sourceSignals.size} mismatch(es)",
            outcome = when {
                sourceSignals.any { it.severity == SystemPropertySeverity.DANGER } -> BootloaderMethodOutcome.DANGER
                sourceSignals.isNotEmpty() -> BootloaderMethodOutcome.WARNING
                observedPropertyCount > 0 -> BootloaderMethodOutcome.CLEAN
                else -> BootloaderMethodOutcome.SUPPORT
            },
            detail = "Cross-source comparison across reflection, getprop, JVM, and native libc reads.",
        ),
        BootloaderMethodResult(
            label = "Cross-check rules",
            summary = if (consistencySignals.isEmpty()) "Aligned" else "${consistencySignals.size} finding(s)",
            outcome = when {
                consistencySignals.any { it.severity == SystemPropertySeverity.DANGER } -> BootloaderMethodOutcome.DANGER
                consistencySignals.isNotEmpty() -> BootloaderMethodOutcome.WARNING
                else -> BootloaderMethodOutcome.CLEAN
            },
            detail = "Raw-boot, lock-state, partition-verity, and build-profile coherence checks.",
        ),
        widevineEvidence.method,
    )
}

internal fun buildImpacts(
    state: BootloaderState,
    evidenceMode: BootloaderEvidenceMode,
    trust: CertificateTrustResult,
    propertyContext: BootloaderPropertyContext,
    bootConsistency: BootConsistencyResult,
    findings: List<BootloaderFinding>,
    widevineEvidence: WidevineBootloaderEvidence,
): List<BootloaderImpact> {
    return buildList {
        when (state) {
            BootloaderState.UNLOCKED -> add(
                BootloaderImpact(
                    text = "Unlocked bootloaders allow custom boot images and can disable or bypass normal verified-boot guarantees.",
                    severity = BootloaderFindingSeverity.DANGER,
                ),
            )

            BootloaderState.FAILED_VERIFICATION -> add(
                BootloaderImpact(
                    text = "Verified Boot failure means the boot chain reported a critical verification problem, which is stronger than a normal custom-ROM signal.",
                    severity = BootloaderFindingSeverity.DANGER,
                ),
            )

            BootloaderState.SELF_SIGNED -> add(
                BootloaderImpact(
                    text = "Self-signed verified boot usually means the bootloader is re-locked against a user-managed key rather than the OEM root of trust.",
                    severity = BootloaderFindingSeverity.WARNING,
                ),
            )

            BootloaderState.LOCKED_UNKNOWN,
            BootloaderState.VERIFIED,
            BootloaderState.UNKNOWN -> Unit
        }

        if (bootConsistency.hasHardAnomaly) {
            add(
                BootloaderImpact(
                    text = "Attestation-vs-runtime contradictions are higher confidence than a single suspicious property because hardware-backed and software-readable boot evidence disagree.",
                    severity = BootloaderFindingSeverity.DANGER,
                ),
            )
        }

        if (propertyContext.warrantyVoid) {
            add(
                BootloaderImpact(
                    text = "Samsung Knox warranty e-fuse appears tripped, which is permanent on supported Samsung devices and often reflects prior unlocking or unofficial boot images.",
                    severity = BootloaderFindingSeverity.DANGER,
                ),
            )
        }

        if (propertyContext.isDebugBuild) {
            add(
                BootloaderImpact(
                    text = "Debuggable or insecure build flags reduce confidence in software-readable boot signals and are not normal for production user builds.",
                    severity = BootloaderFindingSeverity.WARNING,
                ),
            )
        }

        if (evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY) {
            add(
                BootloaderImpact(
                    text = "This result relies on boot properties only. Root or property-hook layers can spoof these values more easily than attestation RootOfTrust.",
                    severity = BootloaderFindingSeverity.INFO,
                ),
            )
        }

        addAll(widevineEvidence.impacts)

        if (findings.none {
                it.severity == BootloaderFindingSeverity.DANGER ||
                    it.severity == BootloaderFindingSeverity.WARNING
            }
        ) {
            add(
                BootloaderImpact(
                    text = "No bootloader or verified-boot signal suggested an unlocked or obviously contradictory boot chain.",
                    severity = BootloaderFindingSeverity.SAFE,
                ),
            )
        }

        add(
            BootloaderImpact(
                text = "Bootloader evidence should still be read alongside TEE, kernel, SU, package, and property detectors because modern spoofing stacks often spread signals across layers.",
                severity = when {
                    !trust.chainSignatureValid -> BootloaderFindingSeverity.DANGER
                    trust.trustRoot == TeeTrustRoot.AOSP -> BootloaderFindingSeverity.WARNING
                    else -> BootloaderFindingSeverity.INFO
                },
            ),
        )
    }
}
