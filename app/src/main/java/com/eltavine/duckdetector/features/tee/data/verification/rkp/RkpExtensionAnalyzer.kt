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
        if (structure.provisioningConsistencyIssue) {
            return TeeRkpState(
                attestationExtensionCount = extensionCount,
                consistencyIssue = "Provisioning info was not adjacent to the trusted attestation certificate.",
                abuseLevel = TeeSignalLevel.WARN,
            )
        }
        val raw = chain[provisioningIndex].getExtensionValue(PROVISIONING_INFO_OID)
            ?: return TeeRkpState(attestationExtensionCount = extensionCount)
        val payload = DerWrapper.unwrapOctetString(raw)
        val map = TinyCborReader(payload).readMap()
        val certsIssued = (map[1] as? Long)?.toInt()
        val validatedEntity = map[4] as? String
        return TeeRkpState(
            provisioned = true,
            serverSigned = true,
            validityDays = chain.firstOrNull()?.let { cert ->
                ((cert.notAfter.time - cert.notBefore.time) / 86_400_000L).toInt()
            },
            validatedEntity = validatedEntity,
            attestationExtensionCount = extensionCount,
            abuseLevel = TeeSignalLevel.INFO,
            abuseSummary = certsIssued?.let {
                "Provisioning info reported approximately $it short-lived certificates in the last 30 days."
            },
        )
    }

    companion object {
        private const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
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

internal object DerWrapper {
    fun unwrapOctetString(data: ByteArray): ByteArray {
        if (data.size < 2 || data[0].toInt() != 0x04) {
            return data
        }
        val lenByte = data[1].toInt() and 0xFF
        return if (lenByte < 0x80) {
            data.copyOfRange(2, data.size)
        } else {
            val lengthBytes = lenByte and 0x7F
            data.copyOfRange(2 + lengthBytes, data.size)
        }
    }
}

internal class TinyCborReader(private val bytes: ByteArray) {
    private var offset = 0

    fun readMap(): Map<Int, Any> {
        val initial = nextByte()
        require(initial shr 5 == 5) { "Expected CBOR map" }
        val count = readLength(initial)
        return buildMap {
            repeat(count) {
                val keyInitial = nextByte()
                require(keyInitial shr 5 == 0) { "CBOR key must be uint" }
                val key = readLength(keyInitial)
                put(key, readValue())
            }
        }
    }

    private fun readValue(): Any {
        val initial = nextByte()
        return when (initial shr 5) {
            0 -> readLength(initial).toLong()
            3 -> {
                val length = readLength(initial)
                String(bytes, offset, length, Charsets.UTF_8).also { offset += length }
            }

            else -> error("Unsupported CBOR major type ${initial shr 5}")
        }
    }

    private fun readLength(initial: Int): Int {
        val info = initial and 0x1F
        return when {
            info < 24 -> info
            info == 24 -> nextByte()
            info == 25 -> (nextByte() shl 8) or nextByte()
            else -> error("Unsupported CBOR length encoding")
        }
    }

    private fun nextByte(): Int = bytes[offset++].toInt() and 0xFF
}
