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

package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterState

class SoterDamageEvaluator {

    fun evaluate(
        serviceReachable: Boolean,
        keyPrepared: Boolean,
        signSessionAvailable: Boolean,
        errorMessage: String?,
        abnormalEnvironment: Boolean = false,
    ): TeeSoterState {
        val available = serviceReachable && keyPrepared && signSessionAvailable
        val damaged = serviceReachable && !available
        val summary = when {
            available -> "Soter checks succeeded: Treble service was reachable and ASK/AuthKey/initSigh all succeeded."
            abnormalEnvironment ->
                "Abnormal Soter environment: Simplified Chinese locale on a likely Soter-supporting device, but PackageManager could not resolve com.tencent.soter.soterserver."
            !serviceReachable -> "Soter check skipped because the Treble service was not reachable."
            errorMessage != null -> withSoterHint(errorMessage)
            !keyPrepared -> "Soter key preparation failed after the Treble service became reachable."
            else -> "Soter signing session initialization failed after the Treble service became reachable."
        }
        return TeeSoterState(
            serviceReachable = serviceReachable,
            keyPrepared = keyPrepared,
            signSessionAvailable = signSessionAvailable,
            available = available,
            damaged = damaged,
            abnormalEnvironment = abnormalEnvironment,
            summary = summary,
        )
    }

    private fun withSoterHint(message: String): String {
        return if (message.contains("soter", ignoreCase = true)) {
            message
        } else {
            "Soter check: $message"
        }
    }
}
