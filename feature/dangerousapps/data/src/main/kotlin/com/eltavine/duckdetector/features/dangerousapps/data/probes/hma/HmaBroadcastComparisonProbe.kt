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
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBroadcastPolicy
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallbackComparison
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallbackObservation
import kotlinx.coroutines.withTimeoutOrNull

internal class HmaBroadcastComparisonProbe {
    suspend fun run(
        callerPackage: String,
        packages: List<String>,
        receive: suspend (String) -> HmaCallbackObservation,
    ): List<HmaBehaviorCheck> {
        val initial = receive(callerPackage)
        var before = initial
        val comparisons = mutableListOf<HmaCallbackComparison>()
        var budgetExpired = false
        // Keep a complete observation only after its trailing control; a cancelled pair is partial coverage.
        if (initial.consistent) {
            budgetExpired = withTimeoutOrNull(BATCH_TIMEOUT_MS) {
                for (packageName in packages) {
                    val first = receive(packageName)
                    val between = receive(callerPackage)
                    val repeat = receive(packageName)
                    val after = receive(callerPackage)
                    comparisons += HmaCallbackComparison(packageName, first, repeat, before, between, after)
                    if (!between.consistent || !after.consistent) break
                    before = after
                }
                true
            } == null
        }
        return HmaBroadcastPolicy.evaluate(initial, comparisons, packages.size, budgetExpired)
    }

    private companion object { const val BATCH_TIMEOUT_MS = 8000L }
}
