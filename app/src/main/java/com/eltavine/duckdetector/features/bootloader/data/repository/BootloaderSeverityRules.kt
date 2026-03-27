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
