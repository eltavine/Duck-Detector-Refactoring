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

import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.tee.data.verification.certificate.CertificateTrustResult
import com.eltavine.duckdetector.features.tee.domain.TeeTrustRoot

internal object BootloaderSeverityRules {

    fun trustRootSeverity(trust: CertificateTrustResult): BootloaderFindingSeverity {
        return when {
            trust.chainLength == 0 -> BootloaderFindingSeverity.DANGER
            !trust.chainSignatureValid || trust.expiredCertificates.isNotEmpty() || trust.issuerMismatches.isNotEmpty() ->
                BootloaderFindingSeverity.DANGER

            trust.trustRoot == TeeTrustRoot.UNKNOWN -> BootloaderFindingSeverity.DANGER
            trust.trustRoot == TeeTrustRoot.AOSP -> BootloaderFindingSeverity.WARNING
            trust.trustRoot == TeeTrustRoot.GOOGLE || trust.trustRoot == TeeTrustRoot.GOOGLE_RKP ->
                BootloaderFindingSeverity.SAFE

            trust.trustRoot == TeeTrustRoot.FACTORY -> BootloaderFindingSeverity.INFO
            else -> BootloaderFindingSeverity.INFO
        }
    }

    fun isKeyPairGenerationFailure(errorMessage: String?): Boolean {
        return errorMessage?.contains("generate a key pair", ignoreCase = true) == true
    }
}
