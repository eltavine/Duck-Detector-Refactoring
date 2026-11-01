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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.native.InitRcTimingNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.InitRcTimingObservation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.cancellation.CancellationException

class InitRcTimingProbe(
    private val context: Context?,
    private val bridge: InitRcTimingNativeBridge = InitRcTimingNativeBridge(),
) {
    suspend fun collect(): InitRcTimingObservation {
        currentCoroutineContext().ensureActive()
        val directory = try {
            context?.cacheDir?.canonicalPath
        } catch (failure: Exception) {
            if (failure is CancellationException) throw failure
            return InitRcTimingObservation(
                collection = InitRcTimingCollection.FILE_FAILED,
                failureDetail = PlatformFailureName.describe(failure),
            )
        } ?: return InitRcTimingObservation(failureDetail = "App-private cache directory unavailable")
        val observation = bridge.collect(directory)
        currentCoroutineContext().ensureActive()
        return observation
    }
}
