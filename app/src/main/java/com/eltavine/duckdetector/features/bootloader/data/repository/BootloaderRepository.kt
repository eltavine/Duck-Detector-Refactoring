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

package com.eltavine.duckdetector.features.bootloader.data.repository

import android.content.Context
import android.os.Build
import com.eltavine.duckdetector.features.bootloader.data.rules.BootloaderCatalog
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderEvidenceMode
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderImpact
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodResult
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderReport
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderStage
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderState
import com.eltavine.duckdetector.features.systemproperties.data.native.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.systemproperties.data.utils.MultiSourcePropertyRead
import com.eltavine.duckdetector.features.systemproperties.data.utils.SystemPropertyConsistencyUtils
import com.eltavine.duckdetector.features.systemproperties.data.utils.SystemPropertyReadUtils
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.features.tee.data.attestation.AndroidAttestationCollector
import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyProbe
import com.eltavine.duckdetector.features.tee.data.verification.boot.BootConsistencyResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.data.verification.certificate.GoogleAttestationRootStore
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class BootloaderRepository(
    context: Context,
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
    private val readUtils: SystemPropertyReadUtils = SystemPropertyReadUtils(),
    private val consistencyUtils: SystemPropertyConsistencyUtils = SystemPropertyConsistencyUtils(),
) {

    private val appContext = context.applicationContext
    private val trustAnalyzer = CertificateTrustAnalyzer(GoogleAttestationRootStore(appContext))
    private val bootConsistencyProbe = BootConsistencyProbe()

    suspend fun scan(): BootloaderReport = withContext(Dispatchers.Default) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                BootloaderReport.failed(throwable.message ?: "Bootloader scan failed.")
            }
    }

    private fun scanInternal(): BootloaderReport {
        val trackedProperties = buildTrackedProperties()
        val coreProperties = BootloaderCatalog.properties.mapTo(linkedSetOf()) { it.property }
        val nativeSnapshot = readUtils.collectNativeSnapshot(trackedProperties.keys)
        val propertyCache = linkedMapOf<String, MultiSourcePropertyRead>()
        val readsByProperty = trackedProperties.mapValues { (property, category) ->
            readUtils.readProperty(
                property = property,
                category = category,
                cache = propertyCache,
                nativeSnapshot = nativeSnapshot,
            )
        }

        val attestation = collector.collect(useStrongBox = false)
        val trust = trustAnalyzer.inspect(attestation.rawCertificates)
        val bootConsistency = bootConsistencyProbe.inspect(attestation)
        val propertyContext = BootloaderPropertyContext.from(readsByProperty)
        val evidenceMode = resolveEvidenceMode(attestation, propertyContext)
        val state = resolveState(attestation, propertyContext)
        val sourceSignals = consistencyUtils.buildSourceMismatchSignals(readsByProperty.values)
        val consistencySignals = consistencyUtils.buildConsistencySignals(
            readsByProperty = readsByProperty,
            nativeSnapshot = nativeSnapshot,
        )

        val findings = buildList {
            addAll(buildStateFindings(state, evidenceMode, attestation, trust, propertyContext))
            addAll(buildAttestationFindings(attestation, trust))
            addAll(buildPropertyFindings(propertyContext, readsByProperty))
            addAll(buildConsistencyFindings(bootConsistency, sourceSignals, consistencySignals))
        }
        val impacts = buildImpacts(
            state = state,
            evidenceMode = evidenceMode,
            trust = trust,
            propertyContext = propertyContext,
            bootConsistency = bootConsistency,
            findings = findings,
        )
        val observedPropertyCount = readsByProperty
            .filterKeys { it in coreProperties }
            .values
            .count { it.preferredValue.isNotBlank() }
        val reflectionHitCount = readsByProperty
            .filterKeys { it in coreProperties }
            .values
            .count {
                it.sourceValues[SystemPropertySource.REFLECTION].isNullOrBlank().not()
            }
        val getpropHitCount = readsByProperty
            .filterKeys { it in coreProperties }
            .values
            .count {
                it.sourceValues[SystemPropertySource.GETPROP].isNullOrBlank().not()
            }
        val methods = buildMethods(
            evidenceMode = evidenceMode,
            attestation = attestation,
            trust = trust,
            bootConsistency = bootConsistency,
            nativeSnapshot = nativeSnapshot,
            observedPropertyCount = observedPropertyCount,
            reflectionHitCount = reflectionHitCount,
            getpropHitCount = getpropHitCount,
            sourceSignals = sourceSignals,
            consistencySignals = consistencySignals,
            propertyContext = propertyContext,
        )

        if (findings.isEmpty() && attestation.errorMessage != null && observedPropertyCount == 0) {
            return BootloaderReport.failed(attestation.errorMessage)
        }

        return BootloaderReport(
            stage = BootloaderStage.READY,
            state = state,
            evidenceMode = evidenceMode,
            trustRoot = trust.trustRoot,
            tier = attestation.tier,
            attestationAvailable = hasAttestation(attestation),
            hardwareBacked = attestation.tier == TeeTier.TEE || attestation.tier == TeeTier.STRONGBOX,
            attestationChainLength = trust.chainLength,
            checkedPropertyCount = BootloaderCatalog.properties.size,
            observedPropertyCount = observedPropertyCount,
            nativePropertyHitCount = nativeSnapshot.nativePropertyHitCount,
            rawBootParamHitCount = nativeSnapshot.bootParamHitCount,
            sourceMismatchCount = sourceSignals.size,
            consistencyFindingCount = bootloaderConsistencyCount(
                bootConsistency,
                sourceSignals,
                consistencySignals
            ),
            findings = findings,
            impacts = impacts,
            methods = methods,
            errorMessage = attestation.errorMessage,
        )
    }

    private fun buildTrackedProperties(): Map<String, SystemPropertyCategory> {
        return buildMap {
            BootloaderCatalog.properties.forEach { spec ->
                put(spec.property, spec.category)
            }
            put("ro.build.type", SystemPropertyCategory.BUILD_PROFILE)
            put("ro.build.tags", SystemPropertyCategory.BUILD_PROFILE)
            put("ro.build.fingerprint", SystemPropertyCategory.BUILD_PROFILE)
        }
    }

    private fun resolveEvidenceMode(
        attestation: AttestationSnapshot,
        propertyContext: BootloaderPropertyContext,
    ): BootloaderEvidenceMode {
        return when {
            hasAttestation(attestation) -> BootloaderEvidenceMode.ATTESTATION
            propertyContext.hasBootEvidence -> BootloaderEvidenceMode.PROPERTIES_ONLY
            else -> BootloaderEvidenceMode.UNAVAILABLE
        }
    }

    private fun resolveState(
        attestation: AttestationSnapshot,
        propertyContext: BootloaderPropertyContext,
    ): BootloaderState {
        val root = attestation.rootOfTrust
        if (root != null && (root.deviceLocked != null || root.verifiedBootState.isNullOrBlank()
                .not())
        ) {
            return when (root.verifiedBootState?.trim()) {
                "Verified" -> BootloaderState.VERIFIED
                "Self-signed" -> BootloaderState.SELF_SIGNED
                "Unverified" -> BootloaderState.UNLOCKED
                "Failed" -> BootloaderState.FAILED_VERIFICATION
                else -> when (root.deviceLocked) {
                    false -> BootloaderState.UNLOCKED
                    true -> BootloaderState.LOCKED_UNKNOWN
                    null -> BootloaderState.UNKNOWN
                }
            }
        }

        return when (propertyContext.bootState) {
            PropertyBootState.GREEN -> BootloaderState.VERIFIED
            PropertyBootState.YELLOW -> BootloaderState.SELF_SIGNED
            PropertyBootState.ORANGE -> BootloaderState.UNLOCKED
            PropertyBootState.RED -> BootloaderState.FAILED_VERIFICATION
            PropertyBootState.UNKNOWN -> when (propertyContext.isLocked) {
                true -> BootloaderState.LOCKED_UNKNOWN
                false -> BootloaderState.UNLOCKED
                null -> BootloaderState.UNKNOWN
            }
        }
    }

    private fun buildStateFindings(
        state: BootloaderState,
        evidenceMode: BootloaderEvidenceMode,
        attestation: AttestationSnapshot,
        trust: CertificateTrustResult,
        propertyContext: BootloaderPropertyContext,
    ): List<BootloaderFinding> {
        return buildList {
            add(
                BootloaderFinding(
                    id = "boot_state",
                    label = "Boot state",
                    value = stateLabel(state, evidenceMode),
                    group = BootloaderFindingGroup.STATE,
                    severity = stateSeverity(state),
                    detail = stateDetail(state, evidenceMode),
                ),
            )
            add(
                BootloaderFinding(
                    id = "evidence_mode",
                    label = "Evidence source",
                    value = evidenceModeLabel(evidenceMode),
                    group = BootloaderFindingGroup.STATE,
                    severity = when (evidenceMode) {
                        BootloaderEvidenceMode.ATTESTATION -> BootloaderFindingSeverity.SAFE
                        BootloaderEvidenceMode.PROPERTIES_ONLY -> BootloaderFindingSeverity.INFO
                        BootloaderEvidenceMode.UNAVAILABLE -> BootloaderFindingSeverity.WARNING
                    },
                    detail = when (evidenceMode) {
                        BootloaderEvidenceMode.ATTESTATION ->
                            "RootOfTrust data was available and took priority over software-readable properties."

                        BootloaderEvidenceMode.PROPERTIES_ONLY ->
                            "Attestation root data was unavailable, so this result falls back to boot properties that can be modified on rooted systems."

                        BootloaderEvidenceMode.UNAVAILABLE ->
                            "Neither attestation RootOfTrust nor readable boot properties were available."
                    },
                ),
            )
            val lockLabel = when (val locked =
                attestation.rootOfTrust?.deviceLocked ?: propertyContext.isLocked) {
                true -> "Locked"
                false -> "Unlocked"
                null -> "Unknown"
            }
            add(
                BootloaderFinding(
                    id = "lock_state",
                    label = "Lock state",
                    value = lockLabel,
                    group = BootloaderFindingGroup.STATE,
                    severity = when (attestation.rootOfTrust?.deviceLocked
                        ?: propertyContext.isLocked) {
                        true -> BootloaderFindingSeverity.SAFE
                        false -> BootloaderFindingSeverity.DANGER
                        null -> BootloaderFindingSeverity.INFO
                    },
                    detail = lockStateDetail(attestation, propertyContext),
                ),
            )
            add(
                BootloaderFinding(
                    id = "trust_root",
                    label = "Trust root",
                    value = trustRootLabel(trust.trustRoot),
                    group = BootloaderFindingGroup.STATE,
                    severity = trustRootSeverity(trust),
                    detail = trustRootDetail(trust),
                ),
            )
        }
    }

    private fun buildAttestationFindings(
        attestation: AttestationSnapshot,
        trust: CertificateTrustResult,
    ): List<BootloaderFinding> {
        if (!hasAttestation(attestation)) {
            val keyPairGenerationFailure =
                BootloaderSeverityRules.isKeyPairGenerationFailure(attestation.errorMessage)
            return listOf(
                BootloaderFinding(
                    id = "attestation_unavailable",
                    label = "Key attestation",
                    value = if (keyPairGenerationFailure) "Failed" else "Unavailable",
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = if (keyPairGenerationFailure) {
                        BootloaderFindingSeverity.DANGER
                    } else {
                        BootloaderFindingSeverity.INFO
                    },
                    detail = attestation.errorMessage
                        ?: "Key attestation did not expose a usable certificate chain.",
                ),
            )
        }

        val root = attestation.rootOfTrust
        return buildList {
            add(
                BootloaderFinding(
                    id = "attestation_tier",
                    label = "Attestation tier",
                    value = tierLabel(attestation.tier),
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = when (attestation.tier) {
                        TeeTier.STRONGBOX,
                        TeeTier.TEE -> BootloaderFindingSeverity.SAFE

                        TeeTier.SOFTWARE -> BootloaderFindingSeverity.WARNING
                        TeeTier.NONE,
                        TeeTier.UNKNOWN -> BootloaderFindingSeverity.INFO
                    },
                    detail = buildString {
                        append("Certificate chain length: ${trust.chainLength}.")
                        if (attestation.challengeVerified) {
                            append(" Challenge matched generated nonce.")
                        }
                    },
                ),
            )
            add(
                BootloaderFinding(
                    id = "attestation_chain",
                    label = "Certificate chain",
                    value = if (trust.chainSignatureValid) "Valid" else "Broken",
                    group = BootloaderFindingGroup.ATTESTATION,
                    severity = when {
                        !trust.chainSignatureValid -> BootloaderFindingSeverity.DANGER
                        trust.expiredCertificates.isNotEmpty() || trust.issuerMismatches.isNotEmpty() ->
                            BootloaderFindingSeverity.DANGER

                        else -> BootloaderFindingSeverity.SAFE
                    },
                    detail = buildChainDetail(trust),
                ),
            )
            root?.verifiedBootState?.let { verifiedBootState ->
                add(
                    BootloaderFinding(
                        id = "attested_boot_state",
                        label = "Attested boot state",
                        value = verifiedBootState,
                        group = BootloaderFindingGroup.ATTESTATION,
                        severity = stateSeverity(
                            resolveState(
                                attestation = attestation,
                                propertyContext = BootloaderPropertyContext.empty(),
                            ),
                        ),
                        detail = "RootOfTrust.verifiedBootState from attestation extension.",
                    ),
                )
            }
            root?.deviceLocked?.let { locked ->
                add(
                    BootloaderFinding(
                        id = "attested_lock",
                        label = "Attested deviceLocked",
                        value = locked.toString(),
                        group = BootloaderFindingGroup.ATTESTATION,
                        severity = if (locked) BootloaderFindingSeverity.SAFE else BootloaderFindingSeverity.DANGER,
                        detail = "RootOfTrust.deviceLocked from attestation extension.",
                    ),
                )
            }
            root?.verifiedBootHashHex?.takeIf { it.isNotBlank() }?.let { hash ->
                add(
                    BootloaderFinding(
                        id = "attested_boot_hash",
                        label = "Attested boot hash",
                        value = shortHex(hash),
                        group = BootloaderFindingGroup.ATTESTATION,
                        severity = if (isAllZeroHex(hash)) {
                            BootloaderFindingSeverity.DANGER
                        } else {
                            BootloaderFindingSeverity.INFO
                        },
                        detail = hash,
                        detailMonospace = true,
                    ),
                )
            }
            root?.verifiedBootKeyHex?.takeIf { it.isNotBlank() }?.let { key ->
                add(
                    BootloaderFinding(
                        id = "attested_boot_key",
                        label = "Attested boot key",
                        value = shortHex(key),
                        group = BootloaderFindingGroup.ATTESTATION,
                        severity = if (isAllZeroHex(key)) {
                            BootloaderFindingSeverity.DANGER
                        } else {
                            BootloaderFindingSeverity.INFO
                        },
                        detail = key,
                        detailMonospace = true,
                    ),
                )
            }
        }
    }

    private fun buildPropertyFindings(
        propertyContext: BootloaderPropertyContext,
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): List<BootloaderFinding> {
        return BootloaderCatalog.properties.mapNotNull { spec ->
            val read = readsByProperty[spec.property] ?: return@mapNotNull null
            val value = read.preferredValue.takeIf { it.isNotBlank() } ?: return@mapNotNull null
            BootloaderFinding(
                id = "prop_${spec.property}",
                label = propertyLabel(spec.property),
                value = propertyBadgeValue(spec.property, value),
                group = BootloaderFindingGroup.PROPERTIES,
                severity = propertySeverity(spec.property, value, propertyContext),
                detail = buildPropertyDetail(spec.property, read, propertyContext),
                detailMonospace = propertyDetailMonospace(spec.property),
            )
        }
    }

    private fun buildConsistencyFindings(
        bootConsistency: BootConsistencyResult,
        sourceSignals: List<SystemPropertySignal>,
        consistencySignals: List<SystemPropertySignal>,
    ): List<BootloaderFinding> {
        val findings = mutableListOf<BootloaderFinding>()

        if (bootConsistency.vbmetaDigestMismatch) {
            findings += BootloaderFinding(
                id = "vbmeta_digest_mismatch",
                label = "Attested hash vs vbmeta digest",
                value = "Mismatch",
                group = BootloaderFindingGroup.CONSISTENCY,
                severity = BootloaderFindingSeverity.DANGER,
                detail = bootConsistency.detail,
            )
        }
        if (bootConsistency.vbmetaDigestMissingWhileAttestedHashPresent) {
            findings += BootloaderFinding(
                id = "vbmeta_digest_missing",
                label = "Attested hash vs vbmeta digest",
                value = "Digest missing",
                group = BootloaderFindingGroup.CONSISTENCY,
                severity = BootloaderFindingSeverity.DANGER,
                detail = bootConsistency.detail,
            )
        }
        if (bootConsistency.verifiedBootHashAllZeros) {
            findings += BootloaderFinding(
                id = "boot_hash_all_zero",
                label = "Attested boot hash",
                value = "All zeros",
                group = BootloaderFindingGroup.CONSISTENCY,
                severity = BootloaderFindingSeverity.DANGER,
                detail = bootConsistency.detail,
            )
        }
        if (bootConsistency.verifiedBootKeyAllZeros) {
            findings += BootloaderFinding(
                id = "boot_key_all_zero",
                label = "Attested boot key",
                value = "All zeros",
                group = BootloaderFindingGroup.CONSISTENCY,
                severity = BootloaderFindingSeverity.DANGER,
                detail = bootConsistency.detail,
            )
        }
        if (bootConsistency.verifiedStateUnlockedMismatch) {
            findings += BootloaderFinding(
                id = "verified_state_unlocked_mismatch",
                label = "Verified state coherence",
                value = "Impossible pair",
                group = BootloaderFindingGroup.CONSISTENCY,
                severity = BootloaderFindingSeverity.DANGER,
                detail = bootConsistency.detail,
            )
        }
        if (!bootConsistency.hasHardAnomaly) {
            findings += BootloaderFinding(
                id = "boot_consistency_clean",
                label = "Attested hash vs vbmeta digest",
                value = when {
                    bootConsistency.runtimePropsAvailable -> "Aligned"
                    else -> "Partial"
                },
                group = BootloaderFindingGroup.CONSISTENCY,
                severity = if (bootConsistency.runtimePropsAvailable) {
                    BootloaderFindingSeverity.SAFE
                } else {
                    BootloaderFindingSeverity.INFO
                },
                detail = bootConsistency.detail,
            )
        }

        sourceSignals.forEach { signal ->
            findings += systemSignalFinding(
                signal = signal,
                group = BootloaderFindingGroup.CONSISTENCY,
            )
        }
        consistencySignals.forEach { signal ->
            findings += systemSignalFinding(
                signal = signal,
                group = BootloaderFindingGroup.CONSISTENCY,
            )
        }

        return findings
    }

    private fun buildImpacts(
        state: BootloaderState,
        evidenceMode: BootloaderEvidenceMode,
        trust: CertificateTrustResult,
        propertyContext: BootloaderPropertyContext,
        bootConsistency: BootConsistencyResult,
        findings: List<BootloaderFinding>,
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

            if (findings.none { it.severity == BootloaderFindingSeverity.DANGER || it.severity == BootloaderFindingSeverity.WARNING }) {
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

    private fun buildMethods(
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
                    bootConsistency.runtimePropsAvailable -> "Aligned"
                    else -> "Partial"
                },
                outcome = when {
                    bootConsistency.hasHardAnomaly -> BootloaderMethodOutcome.DANGER
                    bootConsistency.runtimePropsAvailable -> BootloaderMethodOutcome.CLEAN
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
        )
    }

    private fun stateLabel(
        state: BootloaderState,
        evidenceMode: BootloaderEvidenceMode,
    ): String {
        return when (state) {
            BootloaderState.VERIFIED -> if (evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY) "Locked by props" else "Verified"
            BootloaderState.SELF_SIGNED -> "Self-signed"
            BootloaderState.UNLOCKED -> "Unlocked"
            BootloaderState.FAILED_VERIFICATION -> "Failed"
            BootloaderState.LOCKED_UNKNOWN -> "Locked, state unknown"
            BootloaderState.UNKNOWN -> "Unknown"
        }
    }

    private fun stateDetail(
        state: BootloaderState,
        evidenceMode: BootloaderEvidenceMode,
    ): String {
        return when (state) {
            BootloaderState.VERIFIED -> if (evidenceMode == BootloaderEvidenceMode.PROPERTIES_ONLY) {
                "Boot properties indicate a locked device and do not contradict a verified boot chain, but attestation RootOfTrust was unavailable."
            } else {
                "Attestation reported a verified boot chain rooted in a locked device state."
            }

            BootloaderState.SELF_SIGNED ->
                "Boot verification succeeded against a user-managed root of trust rather than the OEM root."

            BootloaderState.UNLOCKED ->
                "Bootloader appears unlocked or Verified Boot reported an unverified/orange state."

            BootloaderState.FAILED_VERIFICATION ->
                "Verified Boot reported a failed/red state."

            BootloaderState.LOCKED_UNKNOWN ->
                "Device appears locked, but the verified boot color/state was not exposed clearly enough to confirm OEM verification."

            BootloaderState.UNKNOWN ->
                "Neither attestation nor boot properties exposed a stable boot state."
        }
    }

    private fun lockStateDetail(
        attestation: AttestationSnapshot,
        propertyContext: BootloaderPropertyContext,
    ): String {
        val rootLocked = attestation.rootOfTrust?.deviceLocked
        return when {
            rootLocked != null -> "Derived from RootOfTrust.deviceLocked in attestation."
            propertyContext.lockEvidence.isNotEmpty() -> "Derived from ${propertyContext.lockEvidence.joinToString()}."
            else -> "No reliable lock-state evidence surfaced."
        }
    }

    private fun propertyLabel(property: String): String {
        return when (property) {
            BootloaderCatalog.FLASH_LOCKED -> "ro.boot.flash.locked"
            BootloaderCatalog.VERIFIED_BOOT_STATE -> "ro.boot.verifiedbootstate"
            BootloaderCatalog.SECURE_BOOT -> "ro.boot.secureboot"
            BootloaderCatalog.DEBUGGABLE -> "ro.debuggable"
            BootloaderCatalog.SECURE -> "ro.secure"
            BootloaderCatalog.WARRANTY_BIT,
            BootloaderCatalog.WARRANTY_BIT_ALT -> "warranty_bit"

            BootloaderCatalog.KNOX_STATE -> "ro.boot.knox.state"
            BootloaderCatalog.OEM_UNLOCK_SUPPORTED -> "ro.oem_unlock_supported"
            BootloaderCatalog.VBMETA_DEVICE_STATE -> "ro.boot.vbmeta.device_state"
            BootloaderCatalog.VERITYMODE -> "ro.boot.veritymode"
            BootloaderCatalog.VBMETA_HASH_ALG -> "ro.boot.vbmeta.hash_alg"
            BootloaderCatalog.VBMETA_SIZE -> "ro.boot.vbmeta.size"
            BootloaderCatalog.VBMETA_DIGEST -> "ro.boot.vbmeta.digest"
            BootloaderCatalog.AVB_VERSION -> "ro.boot.avb_version"
            BootloaderCatalog.VBMETA_INVALIDATE -> "ro.boot.vbmeta.invalidate_on_error"
            else -> property
        }
    }

    private fun propertyBadgeValue(
        property: String,
        value: String,
    ): String {
        return when (property) {
            BootloaderCatalog.PARTITION_SYSTEM_VERIFIED,
            BootloaderCatalog.PARTITION_VENDOR_VERIFIED,
            BootloaderCatalog.PARTITION_PRODUCT_VERIFIED,
            BootloaderCatalog.PARTITION_SYSTEM_EXT_VERIFIED,
            BootloaderCatalog.PARTITION_ODM_VERIFIED -> when (value) {
                "1" -> "Enforcing"
                "2" -> "Logging"
                "0" -> "Disabled"
                else -> value
            }

            BootloaderCatalog.WARRANTY_BIT,
            BootloaderCatalog.WARRANTY_BIT_ALT -> when (value) {
                "0" -> "Intact"
                "1" -> "Tripped"
                else -> value
            }

            else -> value
        }
    }

    private fun propertySeverity(
        property: String,
        value: String,
        propertyContext: BootloaderPropertyContext,
    ): BootloaderFindingSeverity {
        return when (property) {
            BootloaderCatalog.FLASH_LOCKED,
            BootloaderCatalog.VBMETA_DEVICE_STATE -> when {
                isLockedValue(value) -> BootloaderFindingSeverity.SAFE
                isUnlockedValue(value) -> BootloaderFindingSeverity.DANGER
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.VERIFIED_BOOT_STATE -> when (value.lowercase()) {
                "green" -> BootloaderFindingSeverity.SAFE
                "yellow" -> BootloaderFindingSeverity.WARNING
                "orange", "red" -> BootloaderFindingSeverity.DANGER
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.SECURE_BOOT -> if (value == "1") BootloaderFindingSeverity.SAFE else BootloaderFindingSeverity.WARNING
            BootloaderCatalog.DEBUGGABLE -> if (value == "1") BootloaderFindingSeverity.WARNING else BootloaderFindingSeverity.SAFE
            BootloaderCatalog.SECURE -> if (value == "0") BootloaderFindingSeverity.WARNING else BootloaderFindingSeverity.SAFE
            BootloaderCatalog.WARRANTY_BIT,
            BootloaderCatalog.WARRANTY_BIT_ALT -> when {
                !propertyContext.isSamsungDevice -> BootloaderFindingSeverity.INFO
                value == "1" -> BootloaderFindingSeverity.DANGER
                value == "0" -> BootloaderFindingSeverity.SAFE
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.KNOX_STATE -> when (value.uppercase()) {
                "NORMAL" -> BootloaderFindingSeverity.SAFE
                "TRIPPED" -> BootloaderFindingSeverity.DANGER
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.OEM_UNLOCK_SUPPORTED -> BootloaderFindingSeverity.INFO
            BootloaderCatalog.VERITYMODE -> when (value.lowercase()) {
                "enforcing", "1" -> BootloaderFindingSeverity.SAFE
                "logging", "2" -> BootloaderFindingSeverity.WARNING
                "0", "disabled" -> BootloaderFindingSeverity.DANGER
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.VBMETA_HASH_ALG -> when (value.lowercase()) {
                "sha256", "sha512" -> BootloaderFindingSeverity.SAFE
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.VBMETA_INVALIDATE -> when (value.lowercase()) {
                "1", "yes", "true" -> BootloaderFindingSeverity.SAFE
                "0", "no", "false" -> BootloaderFindingSeverity.WARNING
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.PARTITION_SYSTEM_VERIFIED,
            BootloaderCatalog.PARTITION_VENDOR_VERIFIED,
            BootloaderCatalog.PARTITION_PRODUCT_VERIFIED,
            BootloaderCatalog.PARTITION_SYSTEM_EXT_VERIFIED,
            BootloaderCatalog.PARTITION_ODM_VERIFIED -> when (value) {
                "1" -> BootloaderFindingSeverity.SAFE
                "2" -> BootloaderFindingSeverity.WARNING
                "0" -> BootloaderFindingSeverity.DANGER
                else -> BootloaderFindingSeverity.INFO
            }

            BootloaderCatalog.VBMETA_DIGEST,
            BootloaderCatalog.AVB_VERSION,
            BootloaderCatalog.VBMETA_SIZE -> BootloaderFindingSeverity.INFO

            else -> BootloaderFindingSeverity.INFO
        }
    }

    private fun buildPropertyDetail(
        property: String,
        read: MultiSourcePropertyRead,
        propertyContext: BootloaderPropertyContext,
    ): String {
        val notes = mutableListOf<String>()
        notes += "Source: ${sourceLabel(read.preferredSource)}"
        when (property) {
            BootloaderCatalog.WARRANTY_BIT,
            BootloaderCatalog.WARRANTY_BIT_ALT -> {
                notes += if (propertyContext.isSamsungDevice) {
                    "Samsung Knox warranty_bit is a hardware e-fuse: 0 means intact, 1 means tripped."
                } else {
                    "warranty_bit is mainly meaningful on Samsung devices."
                }
            }

            BootloaderCatalog.KNOX_STATE -> {
                notes += "Samsung Knox state usually reports NORMAL or TRIPPED."
            }

            BootloaderCatalog.VBMETA_DIGEST -> {
                notes += "Compared against attested verifiedBootHash when RootOfTrust is available."
            }

            BootloaderCatalog.VERITYMODE -> {
                notes += "dm-verity modes usually map to enforcing, logging, or disabled."
            }

            BootloaderCatalog.PARTITION_SYSTEM_VERIFIED,
            BootloaderCatalog.PARTITION_VENDOR_VERIFIED,
            BootloaderCatalog.PARTITION_PRODUCT_VERIFIED,
            BootloaderCatalog.PARTITION_SYSTEM_EXT_VERIFIED,
            BootloaderCatalog.PARTITION_ODM_VERIFIED -> {
                notes += "Partition values typically map as 1=enforcing, 2=logging, 0=disabled."
            }
        }
        if (read.sourceValues.count { it.value.isNotBlank() } > 1) {
            notes += "Cross-checked across ${read.sourceValues.count { it.value.isNotBlank() }} sources."
        }
        notes += "Observed value: ${read.preferredValue}"
        return notes.joinToString(separator = "\n")
    }

    private fun propertyDetailMonospace(property: String): Boolean {
        return property == BootloaderCatalog.VBMETA_DIGEST ||
                property == BootloaderCatalog.VBMETA_HASH_ALG ||
                property == BootloaderCatalog.AVB_VERSION
    }

    private fun stateSeverity(state: BootloaderState): BootloaderFindingSeverity {
        return when (state) {
            BootloaderState.VERIFIED -> BootloaderFindingSeverity.SAFE
            BootloaderState.SELF_SIGNED,
            BootloaderState.LOCKED_UNKNOWN -> BootloaderFindingSeverity.WARNING

            BootloaderState.UNLOCKED,
            BootloaderState.FAILED_VERIFICATION -> BootloaderFindingSeverity.DANGER

            BootloaderState.UNKNOWN -> BootloaderFindingSeverity.INFO
        }
    }

    private fun trustRootSeverity(trust: CertificateTrustResult): BootloaderFindingSeverity {
        return BootloaderSeverityRules.trustRootSeverity(trust)
    }

    private fun trustRootDetail(trust: CertificateTrustResult): String {
        return buildString {
            append("Chain length: ${trust.chainLength}. ")
            append("Root classification: ${trustRootLabel(trust.trustRoot)}.")
            if (trust.rootFingerprint != null) {
                appendLine()
                append("Root fingerprint: ${trust.rootFingerprint}")
            }
            if (trust.issuerMismatches.isNotEmpty()) {
                appendLine()
                append(trust.issuerMismatches.joinToString(separator = "\n"))
            }
            if (trust.expiredCertificates.isNotEmpty()) {
                appendLine()
                append(trust.expiredCertificates.joinToString(separator = "\n"))
            }
        }
    }

    private fun buildChainDetail(trust: CertificateTrustResult): String {
        return buildString {
            append("Chain signatures valid: ${trust.chainSignatureValid}.")
            if (trust.googleRootMatched) {
                append(" Google attestation root matched.")
            }
            if (trust.issuerMismatches.isNotEmpty()) {
                appendLine()
                append(trust.issuerMismatches.joinToString(separator = "\n"))
            }
            if (trust.expiredCertificates.isNotEmpty()) {
                appendLine()
                append(trust.expiredCertificates.joinToString(separator = "\n"))
            }
        }
    }

    private fun trustRootLabel(trustRoot: TeeTrustRoot): String {
        return when (trustRoot) {
            TeeTrustRoot.GOOGLE -> "Google"
            TeeTrustRoot.GOOGLE_RKP -> "Google RKP"
            TeeTrustRoot.AOSP -> "AOSP"
            TeeTrustRoot.FACTORY -> "Factory"
            TeeTrustRoot.UNKNOWN -> "Unknown"
        }
    }

    private fun tierLabel(tier: TeeTier): String {
        return when (tier) {
            TeeTier.STRONGBOX -> "StrongBox"
            TeeTier.TEE -> "TEE"
            TeeTier.SOFTWARE -> "Software"
            TeeTier.NONE -> "None"
            TeeTier.UNKNOWN -> "Unknown"
        }
    }

    private fun evidenceModeLabel(mode: BootloaderEvidenceMode): String {
        return when (mode) {
            BootloaderEvidenceMode.ATTESTATION -> "Attestation"
            BootloaderEvidenceMode.PROPERTIES_ONLY -> "Properties"
            BootloaderEvidenceMode.UNAVAILABLE -> "Unavailable"
        }
    }

    private fun sourceLabel(source: SystemPropertySource): String {
        return when (source) {
            SystemPropertySource.REFLECTION -> "Reflection"
            SystemPropertySource.GETPROP -> "getprop"
            SystemPropertySource.JVM -> "System.getProperty"
            SystemPropertySource.BUILD -> "Build constant"
            SystemPropertySource.NATIVE_LIBC -> "Native libc"
            SystemPropertySource.CMDLINE -> "/proc/cmdline"
            SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
        }
    }

    private fun systemSignalFinding(
        signal: SystemPropertySignal,
        group: BootloaderFindingGroup,
    ): BootloaderFinding {
        return BootloaderFinding(
            id = "signal_${signal.property}_${signal.value}",
            label = signal.property,
            value = signal.value,
            group = group,
            severity = when (signal.severity) {
                SystemPropertySeverity.SAFE -> BootloaderFindingSeverity.SAFE
                SystemPropertySeverity.WARNING -> BootloaderFindingSeverity.WARNING
                SystemPropertySeverity.DANGER -> BootloaderFindingSeverity.DANGER
                SystemPropertySeverity.NEUTRAL -> BootloaderFindingSeverity.INFO
            },
            detail = buildString {
                append(signal.description)
                appendLine()
                append("Source: ${sourceLabel(signal.source)}")
                signal.detail?.takeIf { it.isNotBlank() }?.let {
                    appendLine()
                    append(it)
                }
            },
            detailMonospace = true,
        )
    }

    private fun bootloaderConsistencyCount(
        bootConsistency: BootConsistencyResult,
        sourceSignals: List<SystemPropertySignal>,
        consistencySignals: List<SystemPropertySignal>,
    ): Int {
        val bootCount = listOf(
            bootConsistency.vbmetaDigestMismatch,
            bootConsistency.vbmetaDigestMissingWhileAttestedHashPresent,
            bootConsistency.verifiedBootHashAllZeros,
            bootConsistency.verifiedBootKeyAllZeros,
            bootConsistency.verifiedStateUnlockedMismatch,
        ).count { it }
        return bootCount + sourceSignals.size + consistencySignals.size
    }

    private fun hasAttestation(snapshot: AttestationSnapshot): Boolean {
        return snapshot.rawCertificates.isNotEmpty() || snapshot.rootOfTrust != null
    }

    private fun shortHex(value: String): String {
        val cleaned = value.filterNot { it.isWhitespace() || it == ':' }
        return if (cleaned.length > 16) cleaned.take(16) + "…" else cleaned
    }

    private fun isAllZeroHex(value: String?): Boolean {
        val cleaned = value
            ?.filterNot { it.isWhitespace() || it == ':' }
            ?.lowercase()
            .orEmpty()
        return cleaned.isNotBlank() && cleaned.all { it == '0' }
    }

    private fun isLockedValue(value: String): Boolean {
        return value == "1" || value.equals("locked", ignoreCase = true) || value.equals(
            "true",
            ignoreCase = true
        )
    }

    private fun isUnlockedValue(value: String): Boolean {
        return value == "0" || value.equals("unlocked", ignoreCase = true) || value.equals(
            "false",
            ignoreCase = true
        )
    }

    private enum class PropertyBootState {
        GREEN,
        YELLOW,
        ORANGE,
        RED,
        UNKNOWN,
    }

    private data class BootloaderPropertyContext(
        val bootState: PropertyBootState,
        val isLocked: Boolean?,
        val secureBoot: String?,
        val debuggable: String?,
        val secure: String?,
        val warrantyBit: String?,
        val knoxState: String?,
        val verityMode: String?,
        val lockEvidence: List<String>,
        val hasBootEvidence: Boolean,
        val hasDangerProperty: Boolean,
        val hasWarningProperty: Boolean,
        val isDebugBuild: Boolean,
        val warrantyVoid: Boolean,
        val isSamsungDevice: Boolean,
    ) {
        companion object {
            fun from(readsByProperty: Map<String, MultiSourcePropertyRead>): BootloaderPropertyContext {
                val flashLocked =
                    readsByProperty[BootloaderCatalog.FLASH_LOCKED]?.preferredValue.orEmpty()
                val vbmetaDeviceState =
                    readsByProperty[BootloaderCatalog.VBMETA_DEVICE_STATE]?.preferredValue.orEmpty()
                val secureBoot = readsByProperty[BootloaderCatalog.SECURE_BOOT]?.preferredValue
                val debuggable = readsByProperty[BootloaderCatalog.DEBUGGABLE]?.preferredValue
                val secure = readsByProperty[BootloaderCatalog.SECURE]?.preferredValue
                val warrantyBit = listOf(
                    readsByProperty[BootloaderCatalog.WARRANTY_BIT]?.preferredValue,
                    readsByProperty[BootloaderCatalog.WARRANTY_BIT_ALT]?.preferredValue,
                ).firstOrNull { it.isNullOrBlank().not() }
                val knoxState = readsByProperty[BootloaderCatalog.KNOX_STATE]?.preferredValue
                val verityMode = readsByProperty[BootloaderCatalog.VERITYMODE]?.preferredValue
                val verifiedBoot =
                    readsByProperty[BootloaderCatalog.VERIFIED_BOOT_STATE]?.preferredValue.orEmpty()

                val lockEvidence = buildList {
                    if (flashLocked.isNotBlank()) add(BootloaderCatalog.FLASH_LOCKED)
                    if (vbmetaDeviceState.isNotBlank()) add(BootloaderCatalog.VBMETA_DEVICE_STATE)
                    if (secureBoot.isNullOrBlank().not()) add(BootloaderCatalog.SECURE_BOOT)
                }

                val isLocked = when {
                    flashLocked == "1" -> true
                    flashLocked == "0" -> false
                    vbmetaDeviceState.equals("locked", ignoreCase = true) -> true
                    vbmetaDeviceState.equals("unlocked", ignoreCase = true) -> false
                    secureBoot == "1" -> true
                    else -> null
                }

                val bootState = when (verifiedBoot.lowercase()) {
                    "green" -> PropertyBootState.GREEN
                    "yellow" -> PropertyBootState.YELLOW
                    "orange" -> PropertyBootState.ORANGE
                    "red" -> PropertyBootState.RED
                    else -> PropertyBootState.UNKNOWN
                }

                val isSamsungDevice = Build.MANUFACTURER.equals("samsung", ignoreCase = true)
                val warrantyVoid =
                    warrantyBit == "1" || knoxState.equals("TRIPPED", ignoreCase = true)
                val isDebugBuild = debuggable == "1" || secure == "0"
                val hasDangerProperty = when {
                    isLocked == false -> true
                    bootState == PropertyBootState.ORANGE || bootState == PropertyBootState.RED -> true
                    warrantyVoid -> true
                    verityMode.equals("disabled", ignoreCase = true) || verityMode == "0" -> true
                    else -> false
                }
                val hasWarningProperty = when {
                    bootState == PropertyBootState.YELLOW -> true
                    verityMode.equals("logging", ignoreCase = true) || verityMode == "2" -> true
                    isDebugBuild -> true
                    else -> false
                }

                return BootloaderPropertyContext(
                    bootState = bootState,
                    isLocked = isLocked,
                    secureBoot = secureBoot,
                    debuggable = debuggable,
                    secure = secure,
                    warrantyBit = warrantyBit,
                    knoxState = knoxState,
                    verityMode = verityMode,
                    lockEvidence = lockEvidence,
                    hasBootEvidence = isLocked != null || bootState != PropertyBootState.UNKNOWN || secureBoot.isNullOrBlank()
                        .not(),
                    hasDangerProperty = hasDangerProperty,
                    hasWarningProperty = hasWarningProperty,
                    isDebugBuild = isDebugBuild,
                    warrantyVoid = warrantyVoid,
                    isSamsungDevice = isSamsungDevice,
                )
            }

            fun empty(): BootloaderPropertyContext {
                return BootloaderPropertyContext(
                    bootState = PropertyBootState.UNKNOWN,
                    isLocked = null,
                    secureBoot = null,
                    debuggable = null,
                    secure = null,
                    warrantyBit = null,
                    knoxState = null,
                    verityMode = null,
                    lockEvidence = emptyList(),
                    hasBootEvidence = false,
                    hasDangerProperty = false,
                    hasWarningProperty = false,
                    isDebugBuild = false,
                    warrantyVoid = false,
                    isSamsungDevice = false,
                )
            }
        }
    }
}
