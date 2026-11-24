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

import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun MutableList<TeeEvidenceItem>.addKeyMaterialAndBinderIndicators(artifacts: TeeScanArtifacts) {
    if (artifacts.pairConsistency.executed && !artifacts.pairConsistency.keyMatchesCertificate) {
        add(
            fact(
                "Key pair",
                "Leaf certificate key did not verify fresh local signatures.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.aesGcm.executed && !artifacts.aesGcm.roundTripSucceeded) {
        add(
            fact(
                "AES-GCM",
                "AndroidKeyStore AES-GCM round-trip failed.",
                TeeSignalLevel.FAIL,
            )
        )
    }
    val aesGcmAuthorizationFailures = aesGcmAuthorizationFailures(artifacts.aesGcm)
    if (artifacts.aesGcm.executed && aesGcmAuthorizationFailures.isNotEmpty()) {
        add(
            fact(
                "AES-GCM",
                "AndroidKeyStore AES-GCM accepted unauthorized parameters: ${aesGcmAuthorizationFailures.joinToString("; ")}.",
                TeeSignalLevel.FAIL,
            )
        )
    }
    if (artifacts.aesGcm.executed && artifacts.aesGcm.insideSecureHardware == false) {
        add(
            fact(
                "AES-GCM",
                "AndroidKeyStore AES-GCM key was software-backed instead of secure hardware.",
                TeeSignalLevel.WARN,
            )
        )
    }
    val keyMintCryptoFailures = keyMintCryptoFailures(artifacts)
    if (keyMintCryptoFailures.isNotEmpty()) {
        add(
            fact(
                "KeyMint crypto",
                "Hardware-backed KeyMint failed crypto capability checks: ${keyMintCryptoFailures.joinToString("; ")}.",
                TeeSignalLevel.FAIL,
            )
        )
    }
    if (artifacts.lifecycle.executed &&
        (!artifacts.lifecycle.deleteRemovedAlias || !artifacts.lifecycle.regeneratedFreshMaterial)
    ) {
        add(
            fact(
                "Lifecycle",
                "Delete/regenerate behavior contradicted a clean keystore path.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.pureCertificate.executed && !artifacts.pureCertificate.pureCertificateReturnsNullKey) {
        add(
            fact(
                "Pure certificate",
                "getKey() returned a key object for a certificate-only entry.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.pureCertificateSecurityLevel.executed &&
        artifacts.pureCertificateSecurityLevel.securityLevelPresent
    ) {
        add(
            fact(
                "Pure certificate",
                "Certificate-only entry exposed Keystore2 security-level metadata.",
                TeeSignalLevel.FAIL
            )
        )
    }
    val operationErrorPath = artifacts.operationErrorPath
    if (operationErrorPath.executed && operationErrorPath.keystore2SemanticsDiverged) {
        add(
            fact(
                "Operation path",
                "Keystore2 operation error handling diverged from checks keystore2 itself enforces.",
                TeeSignalLevel.FAIL
            )
        )
    } else if (operationErrorPath.executed && operationErrorPath.updateAadUnexpectedlyAccepted) {
        add(
            fact(
                "Operation path",
                "updateAad was accepted on a signing operation. AOSP's reference KeyMint rejects it, but the HAL does not require an error, so this can be vendor behaviour.",
                TeeSignalLevel.WARN
            )
        )
    }
    if (artifacts.biometricIntegration.executed &&
        artifacts.biometricIntegration.strongBiometricAvailable &&
        (!artifacts.biometricIntegration.keyCreated || !artifacts.biometricIntegration.keyRetrieved)
    ) {
        add(
            fact(
                "Biometric TEE",
                "Strong biometric was available, but user-auth-bound key creation or retrieval failed.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.binderHookBootstrap.executed && !artifacts.binderHookBootstrap.hookInstalled) {
        add(
            fact(
                "Binder hook",
                "Binder hook bootstrap did not complete successfully.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.binderPatchMode.executed &&
        artifacts.binderPatchMode.hookInstalled &&
        (artifacts.binderPatchMode.leafDiffers || artifacts.binderPatchMode.chainDiffers)
    ) {
        add(
            fact(
                "Patch mode",
                "generateKey and getKeyEntry returned different certificate materials.",
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.binderChainConsistency.executed &&
        (
            !artifacts.binderChainConsistency.hookInstalled ||
                artifacts.binderChainConsistency.suspiciousLeafIssuerSpki ||
                !artifacts.binderChainConsistency.activeProbeSecondCycleSucceeded ||
                !artifacts.binderChainConsistency.deleteEntryRemovedAlias ||
                (artifacts.binderChainConsistency.binderMaterialAvailable &&
                    !artifacts.binderChainConsistency.chainMatches) ||
                (artifacts.binderChainConsistency.generateMaterialAvailable &&
                    artifacts.binderChainConsistency.binderMaterialAvailable &&
                    (
                        !artifacts.binderChainConsistency.generateVsGetKeyEntryLeafMatches ||
                            !artifacts.binderChainConsistency.generateVsGetKeyEntryChainMatches
                        ))
            )
    ) {
        add(
            fact(
                "Binder chain",
                if (!artifacts.binderChainConsistency.hookInstalled) {
                    "Binder capture hook bootstrap failed."
                } else {
                    "Java KeyStore, generateKey, and getKeyEntry certificate materials diverged."
                },
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.updateSubcomponent.keyNotFoundStyleFailure || grantUpdateSubcomponentFailed(artifacts)) {
        add(
            fact(
                "Update path",
                updateSubcomponentFailureSummary(artifacts),
                TeeSignalLevel.FAIL
            )
        )
    }
}

internal fun MutableList<TeeEvidenceItem>.addNativeAndStrongBoxIndicators(artifacts: TeeScanArtifacts) {
    if (artifacts.native.leafDerPrimaryDetected) {
        add(
            fact(
                "TS leaf DER",
                "Primary TrickyStore DER fingerprint matched locally.",
                TeeSignalLevel.FAIL
            )
        )
    }
    // The GOT, prologue and honeypot checks each observe one mechanism, an intercepted binder ioctl in
    // this process, so together they are one finding. Only the process map hit is a separate mechanism.
    val ioctlInterception = buildList {
        if (artifacts.native.gotHookDetected) add("libbinder ioctl GOT entry differed from libc.")
        if (artifacts.native.inlineHookDetected) add("ioctl prologue looked patched or redirected.")
        if (artifacts.native.honeypotDetected) add("Keystore-style binder honeypot triggered abnormal ioctl timing.")
    }
    if (ioctlInterception.isNotEmpty()) {
        add(
            fact(
                "TrickyStore ioctl",
                ioctlInterception.joinToString(separator = " "),
                TeeSignalLevel.FAIL
            )
        )
    }
    if (artifacts.native.trickyStoreMapsHitDetected) {
        add(
            fact(
                "TrickyStore",
                "A library mapped into this process matched TrickyStore's name.",
                TeeSignalLevel.FAIL
            )
        )
    }
    artifacts.strongBox.hardFailures.forEach { message ->
        add(fact("StrongBox", message, TeeSignalLevel.FAIL))
    }
}
