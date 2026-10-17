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

package com.eltavine.duckdetector

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.report.DetectorHeadline
import com.eltavine.duckdetector.sdk.DuckDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises a catalogued detector through the same scanner and export contract as an SDK host. */
@RunWith(AndroidJUnit4::class)
class DetectorRuntimeSmokeTest {
    @Test fun scanSelectedDetectorTwice() = runBlocking(Dispatchers.IO) {
        val id = InstrumentationRegistry.getArguments().getString("detectorId")
            ?: error("Supply -e detectorId <catalog id>")
        val detector = DuckDetector.detectors.single { it.id.value == id }
        repeat(2) { scan(detector) }
    }

    private suspend fun <R : Any, M : DetectorHeadline> scan(detector: Detector<R, M>) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val scanner = detector.createScanner(context)
        val model = detector.describe(scanner.scan())
        val report = detector.export(model)
        assertTrue(report.title.isNotBlank())
        assertTrue(report.blocks.isNotEmpty())
        Log.i("DetectorRuntimeSmoke", "${detector.id}: ${report.verdict}")
        report.blocks.forEach { block ->
            block.toString().chunked(3000).forEach { Log.i("DetectorRuntimeSmoke", it) }
        }
    }
}
