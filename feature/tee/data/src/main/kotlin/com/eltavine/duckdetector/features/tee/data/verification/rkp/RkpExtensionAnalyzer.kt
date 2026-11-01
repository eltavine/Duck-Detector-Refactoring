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

package com.eltavine.duckdetector.features.tee.data.verification.rkp

import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel
import com.eltavine.duckdetector.features.tee.data.verification.certificate.ChainStructureResult
import java.security.cert.X509Certificate

class RkpExtensionAnalyzer {

    fun analyze(
        chain: List<X509Certificate>,
        structure: ChainStructureResult,
        googleRootMatched: Boolean,
        chainSignatureValid: Boolean,
    ): TeeRkpState {
        val extensionCount = structure.attestationExtensionCount
        val provisioningIndex =
            structure.provisioningIndex ?: chain.indices.reversed().firstOrNull {
                chain[it].getExtensionValue(PROVISIONING_INFO_OID) != null
            } ?: -1
        if (provisioningIndex < 0) {
            return TeeRkpState(
                attestationExtensionCount = extensionCount,
                consistencyIssue = structure.consistencyIssueOrNull(),
            )
        }
        if (!googleRootMatched) {
            return TeeRkpState(
                attestationExtensionCount = extensionCount,
                consistencyIssue = "Provisioning info was present, but the chain did not terminate at a Google attestation root.",
            )
        }
        if (
            structure.provisioningConsistencyIssue ||
            structure.trustedAttestationIndex == null ||
            provisioningIndex != structure.trustedAttestationIndex + 1
        ) {
            return TeeRkpState(
                attestationExtensionCount = extensionCount,
                consistencyIssue = "Provisioning info was not adjacent to the trusted attestation certificate.",
                abuseLevel = TeeSignalLevel.WARN,
            )
        }
        // A pinned root alone does not authenticate the intermediate carrying this extension.
        if (!chainSignatureValid) {
            return TeeRkpState(
                provisioned = true,
                attestationExtensionCount = extensionCount,
                consistencyIssue = "Provisioning info was not authenticated because local chain signatures failed.",
            )
        }
        val raw = chain[provisioningIndex].getExtensionValue(PROVISIONING_INFO_OID)
            ?: return TeeRkpState(attestationExtensionCount = extensionCount)
        val info = RkpProvisioningInfoParser().parse(raw)
        return TeeRkpState(
            provisioned = true,
            serverSigned = true,
            validityDays = chain.firstOrNull()?.let { cert ->
                ((cert.notAfter.time - cert.notBefore.time) / 86_400_000L).toInt()
            },
            validatedEntity = info.validatedEntity,
            provisioningManufacturer = info.manufacturer,
            certsIssued = info.certsIssued,
            buildMetadata = info.buildMetadata,
            provisioningInfoIssue = info.issue,
            attestationExtensionCount = extensionCount,
            abuseLevel = TeeSignalLevel.INFO,
            abuseSummary = info.certsIssued?.let {
                "Provisioning info reported approximately $it short-lived certificates in the last 30 days."
            },
        )
    }

    companion object {
        private const val PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30"
    }
}

private fun ChainStructureResult.consistencyIssueOrNull(): String? {
    return if (provisioningConsistencyIssue) {
        "Provisioning info was not adjacent to the trusted attestation certificate."
    } else {
        null
    }
}
