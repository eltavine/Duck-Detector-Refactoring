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

import android.os.Build
import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot

class IdAttestationProbe {

    fun inspect(snapshot: AttestationSnapshot): IdAttestationResult {
        val comparisons = listOf(
            "brand" to (snapshot.deviceInfo.brand to Build.BRAND),
            "device" to (snapshot.deviceInfo.device to Build.DEVICE),
            "product" to (snapshot.deviceInfo.product to Build.PRODUCT),
            "manufacturer" to (snapshot.deviceInfo.manufacturer to Build.MANUFACTURER),
            "model" to (snapshot.deviceInfo.model to Build.MODEL),
        )
        val unavailable = comparisons.mapNotNull { (label, pair) ->
            if (pair.first.isNullOrBlank()) label else null
        }
        val mismatches = comparisons.mapNotNull { (label, pair) ->
            val attested = pair.first
            val runtime = pair.second
            when {
                attested.isNullOrBlank() -> null
                attested.equals(runtime, ignoreCase = true) -> null
                else -> "$label=$attested, runtime=$runtime"
            }
        }
        val detail = when {
            mismatches.isNotEmpty() -> "Attested identifiers differ from the current build fields."
            unavailable.size == comparisons.size -> "Attestation did not expose any comparable device identifiers."
            unavailable.isNotEmpty() -> "Attested identifiers were only partially available."
            else -> "Comparable attested identifiers matched the current build fields."
        }
        return IdAttestationResult(
            mismatches = mismatches,
            unavailableFields = unavailable,
            detail = detail,
            probeRan = true,
        )
    }
}

data class IdAttestationResult(
    val mismatches: List<String>,
    val unavailableFields: List<String>,
    val detail: String,
    val probeRan: Boolean = true,
)
