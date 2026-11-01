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

package com.eltavine.duckdetector.features.tee.data.repository

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.capability.attestation.data.AndroidAttestationCollector
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.tee.data.native.TeeNativeBridge
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefsStore
import com.eltavine.duckdetector.features.tee.data.report.TeeReportReducer
import com.eltavine.duckdetector.features.tee.data.report.TeeScanArtifacts
import com.eltavine.duckdetector.features.tee.data.soter.SoterCapabilityProbe
import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyProbe
import com.eltavine.duckdetector.capability.attestation.data.CertificateTrustAnalyzer
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureAnalyzer
import com.eltavine.duckdetector.capability.attestation.data.GoogleAttestationRootStore
import com.eltavine.duckdetector.features.tee.data.verification.crl.CrlStatusService
import com.eltavine.duckdetector.features.tee.data.verification.keystore.SupplementaryAttestationInfoProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.TimingSideChannelProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PostProcessingResult
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpProvisionedManufacturerProbe
import com.eltavine.duckdetector.features.tee.data.verification.keystore.VintfKeyMintVersionProbe
import com.eltavine.duckdetector.features.tee.data.verification.rkp.RkpExtensionAnalyzer
import com.eltavine.duckdetector.features.tee.domain.TeeReport
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class TeeRepository(
    context: Context,
    private val collector: AndroidAttestationCollector = AndroidAttestationCollector(),
    private val nativeBridge: TeeNativeBridge = TeeNativeBridge(),
    private val reducer: TeeReportReducer = TeeReportReducer(),
) : DetectorScanner<TeeReport> {

    private val appContext = context.applicationContext
    private val consentStore: TeeNetworkPrefsStore = TeeNetworkConsentStore.getInstance(appContext)
    private val bootConsistencyProbe = BootConsistencyProbe()
    private val trustAnalyzer = CertificateTrustAnalyzer(GoogleAttestationRootStore(appContext))
    private val chainStructureAnalyzer = ChainStructureAnalyzer()
    private val rkpAnalyzer = RkpExtensionAnalyzer()
    private val crlStatusService = CrlStatusService(appContext, consentStore)
    private val deepCheckRunner = TeeDeepCheckRunner(appContext, collector, trustAnalyzer)
    private val timingSideChannelProbe = TimingSideChannelProbe()
    private val supplementaryAttestationInfoProbe = SupplementaryAttestationInfoProbe(appContext)
    private val vintfKeyMintVersionProbe = VintfKeyMintVersionProbe()
    private val postProcessingProbe = Keystore2PostProcessingProbe()
    private val rkpProvisionedManufacturerProbe = RkpProvisionedManufacturerProbe()
    private val soterProbe = SoterCapabilityProbe(appContext)

    override suspend fun scan(): TeeReport = withContext(Dispatchers.IO) {
        runCatching {
            val snapshot = collector.collect(useStrongBox = false)
            val trust = trustAnalyzer.inspect(snapshot.rawCertificates)
            val chainStructure = chainStructureAnalyzer.inspect(snapshot.rawCertificates)
            val rkp = rkpAnalyzer.analyze(
                snapshot.rawCertificates,
                chainStructure,
                trust.googleRootMatched,
                trust.chainSignatureValid,
            )
            val crl = crlStatusService.inspect(snapshot.rawCertificates)
            val native =
                nativeBridge.collectSnapshot(snapshot.rawCertificates.firstOrNull()?.encoded)
            val soter = runCatching { soterProbe.inspect() }.getOrDefault(TeeSoterState())
            val bootConsistency = bootConsistencyProbe.inspect(snapshot)
            val supplementaryAttestationInfo = supplementaryAttestationInfoProbe.inspect(snapshot)
            val vintfKeyMintVersion = vintfKeyMintVersionProbe.inspect(snapshot)
            // 这条探针要成对生成带 attestation 的 key，代价明显，因此只在硬件 KeyMint 层级下运行
            // This probe generates attested keys pairwise and is visibly expensive, so it only runs on a hardware KeyMint tier.
            // keystore2 的 RkpdProvisioned 分支从 Android 15 起才有 process_certificate_chain 调用点
            // keystore2's RkpdProvisioned arm has no process_certificate_chain call site before Android 15
            val postProcessing = if (Build.VERSION.SDK_INT < 35) {
                Keystore2PostProcessingResult(
                    probeRan = false,
                    detail = "Skipped because keystore2 has no certificate post-processing call site below Android 15.",
                )
            } else if (snapshot.tier == TeeTier.TEE || snapshot.tier == TeeTier.STRONGBOX) {
                runCatching {
                    postProcessingProbe.inspect(useStrongBox = snapshot.tier == TeeTier.STRONGBOX)
                }.getOrElse {
                    Keystore2PostProcessingResult(
                        probeRan = false,
                        detail = "Keystore2 post-processing probe failed to start: ${it.message ?: PlatformFailureName.of(it)}",
                    )
                }
            } else {
                Keystore2PostProcessingResult(
                    probeRan = false,
                    detail = "Skipped because the device did not expose a hardware-backed KeyMint tier.",
                )
            }
            val timingSideChannel = timingSideChannelProbe.inspect(
                useStrongBox = false,
                nativeSnapshot = native,
                appAttestKeyAdvertised = appAttestKeyAdvertised(),
            )
            val deepChecks = deepCheckRunner.collect(
                useStrongBox = snapshot.tier == TeeTier.STRONGBOX,
                deepChecksAllowed = snapshot.tier == TeeTier.TEE || snapshot.tier == TeeTier.STRONGBOX,
                snapshot = snapshot,
                vintfKeyMintVersion = vintfKeyMintVersion,
                timingSideChannel = timingSideChannel,
            )

            reducer.reduce(
                TeeScanArtifacts(
                    snapshot = snapshot,
                    trust = trust,
                    chainStructure = chainStructure,
                    rkp = rkp,
                    crl = crl,
                    pairConsistency = deepChecks.pairConsistency,
                    aesGcm = deepChecks.aesGcm,
                    lifecycle = deepChecks.lifecycle,
                    keyMintCapability = deepChecks.keyMintCapability,
                    timing = deepChecks.timing,
                    timingSideChannel = deepChecks.timingSideChannel,
                    oversizedChallenge = deepChecks.oversizedChallenge,
                    keyboxImport = deepChecks.keyboxImport,
                    importKeyRetainedAttestationNarrative = deepChecks.importKeyRetainedAttestationNarrative,
                    supplementaryAttestationInfo = supplementaryAttestationInfo,
                    vintfKeyMintVersion = vintfKeyMintVersion,
                    keystore2Hook = deepChecks.keystore2Hook,
                    generateModeParcelFingerprint = deepChecks.generateModeParcelFingerprint,
                    postProcessing = postProcessing,
                    rkpProvisionedManufacturer = rkpProvisionedManufacturerProbe.inspect(rkp, snapshot),
                    grantDomainFullChainSplit = deepChecks.grantDomainFullChainSplit,
                    syntheticGrantGranteeBlindReadback = deepChecks.syntheticGrantGranteeBlindReadback,
                    syntheticGrantGetKeyEntryAccessVectorBlindness =
                        deepChecks.syntheticGrantGetKeyEntryAccessVectorBlindness,
                    grantSelfDomainFullChainSplit = deepChecks.grantSelfDomainFullChainSplit,
                    legacyKeystorePath = deepChecks.legacyKeystorePath,
                    listEntriesConsistency = deepChecks.listEntriesConsistency,
                    listEntriesBatched = deepChecks.listEntriesBatched,
                    keyMetadataSemantics = deepChecks.keyMetadataSemantics,
                    keyMetadataShape = deepChecks.keyMetadataShape,
                    pureCertificate = deepChecks.pureCertificate,
                    pureCertificateSecurityLevel = deepChecks.pureCertificateSecurityLevel,
                    operationErrorPath = deepChecks.operationErrorPath,
                    biometricIntegration = deepChecks.biometricIntegration,
                    binderHookBootstrap = deepChecks.binderHookBootstrap,
                    binderPatchMode = deepChecks.binderPatchMode,
                    binderChainConsistency = deepChecks.binderChainConsistency,
                    updateSubcomponent = deepChecks.updateSubcomponent,
                    updateSubcomponentStaleResponsePersistence =
                        deepChecks.updateSubcomponentStaleResponsePersistence,
                    pruning = deepChecks.pruning,
                    dualAlgorithm = deepChecks.dualAlgorithm,
                    idAttestation = deepChecks.idAttestation,
                    strongBox = deepChecks.strongBox,
                    native = native,
                    soter = soter,
                    bootConsistency = bootConsistency,
                ),
            )
        }.getOrElse { throwable ->
            TeeReport.failed(throwable.message ?: "TEE scan failed.")
        }
    }

    // FEATURE_KEYSTORE_APP_ATTEST_KEY arrived with keystore2 in API 31; earlier releases have no ATTEST_KEY purpose.
    private fun appAttestKeyAdvertised(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)


}
