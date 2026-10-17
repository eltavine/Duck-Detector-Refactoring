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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorPolicy
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallOutcome
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaExceptionObservation
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

internal class HmaExceptionProbe {
    suspend fun run(
        kind: HmaCheckKind,
        callerPackage: String,
        packages: List<String>,
        call: (String) -> HmaCallOutcome,
    ): HmaBehaviorCheck {
        val before = call(callerPackage)
        val observations = if (before == HmaCallOutcome.SECURITY_EXCEPTION) {
            packages.map { packageName ->
                coroutineContext.ensureActive()
                HmaExceptionObservation(packageName, call(packageName), call(packageName))
            }
        } else emptyList()
        return HmaBehaviorPolicy.exceptions(kind, before, call(callerPackage), observations)
    }
}
