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

package com.eltavine.duckdetector.core.startup.preload

import android.content.Intent

object EarlyMountPreloadStore {

    @Volatile
    private var intentResult: EarlyMountPreloadResult = EarlyMountPreloadResult.empty()

    @Volatile
    private var bridge: EarlyMountPreloadBridge = EarlyMountPreloadBridge()

    fun capture(intent: Intent?) {
        val captured = EarlyMountPreloadResult.fromIntent(intent)
        if (captured.hasRun) {
            intentResult = captured
        }
    }

    fun currentResult(): EarlyMountPreloadResult {
        return selectPreferred(
            nativeResult = bridge.getStoredResult(),
            intentOnlyResult = intentResult,
        )
    }

    internal fun capture(values: Map<String, Any?>) {
        val captured = EarlyMountPreloadResult.fromCapturedValues(values)
        if (captured.hasRun) {
            intentResult = captured
        }
    }

    internal fun selectPreferred(
        nativeResult: EarlyMountPreloadResult,
        intentOnlyResult: EarlyMountPreloadResult,
    ): EarlyMountPreloadResult {
        return when {
            nativeResult.hasRun -> nativeResult
            intentOnlyResult.hasRun -> intentOnlyResult
            else -> EarlyMountPreloadResult.empty()
        }
    }

    internal fun replaceBridgeForTesting(testBridge: EarlyMountPreloadBridge) {
        bridge = testBridge
    }

    internal fun resetForTesting() {
        intentResult = EarlyMountPreloadResult.empty()
        bridge = EarlyMountPreloadBridge()
    }
}
