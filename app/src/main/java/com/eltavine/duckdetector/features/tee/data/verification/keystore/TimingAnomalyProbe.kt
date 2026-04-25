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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import com.eltavine.duckdetector.features.tee.data.keystore.AndroidKeyStoreTools
import java.security.KeyStore
import java.security.Signature
import kotlin.math.sqrt

class TimingAnomalyProbe {

    fun inspect(
        keyStore: KeyStore = AndroidKeyStoreTools.loadKeyStore(),
        useStrongBox: Boolean = false,
    ): TimingAnomalyResult {
        val alias = "duck_timing_probe_${System.nanoTime()}"
        return runCatching {
            AndroidKeyStoreTools.generateSigningEcKey(
                keyStore = keyStore,
                alias = alias,
                subject = "CN=DuckDetector Timing Probe, O=Eltavine",
                useStrongBox = useStrongBox,
            )
            val privateKey = AndroidKeyStoreTools.readPrivateKey(keyStore, alias)
                ?: return TimingAnomalyResult(
                    suspicious = false,
                    detail = "Timing probe could not read the generated private key.",
                )
            repeat(5) {
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                signature.update("warmup_$it".encodeToByteArray())
                signature.sign()
            }
            val samples = buildList {
                repeat(12) {
                    val signature = Signature.getInstance("SHA256withECDSA")
                    val payload = "timing_sample_$it".encodeToByteArray()
                    val start = System.nanoTime()
                    signature.initSign(privateKey)
                    signature.update(payload)
                    signature.sign()
                    add((System.nanoTime() - start) / 1_000.0)
                }
            }.sorted()
            val median = samples[samples.size / 2]
            val mean = samples.average()
            val variance = samples.map { (it - mean) * (it - mean) }.average()
            val cv = if (mean > 0.0) sqrt(variance) / mean else 0.0
            val jitterRatio = if (samples.first() > 0.0) {
                (samples.last() - samples.first()) / samples.first()
            } else {
                0.0
            }
            val suspicious = median < 100.0 || (median < 200.0 && cv < 0.10 && jitterRatio < 0.15)
            TimingAnomalyResult(
                suspicious = suspicious,
                medianMicros = median.toInt(),
                coefficientOfVariation = cv,
                jitterRatio = jitterRatio,
                detail = if (suspicious) {
                    "Signing looked unusually fast and steady (median=${median.toInt()}us, cv=${
                        "%.2f".format(
                            cv
                        )
                    }, jitter=${"%.2f".format(jitterRatio)})."
                } else {
                    "Signing latency stayed within a plausible hardware-backed range (median=${median.toInt()}us)."
                },
            )
        }.getOrElse { throwable ->
            TimingAnomalyResult(
                suspicious = false,
                detail = throwable.message ?: "Timing probe failed.",
            )
        }.also {
            AndroidKeyStoreTools.safeDelete(keyStore, alias)
        }
    }
}

data class TimingAnomalyResult(
    val suspicious: Boolean,
    val medianMicros: Int? = null,
    val coefficientOfVariation: Double? = null,
    val jitterRatio: Double? = null,
    val detail: String,
)
