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

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAppZygoteTimingVerdict
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.sdk.DuckDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Opt-in acquisition assertions for an installed host with App Zygote enabled. */
@RunWith(AndroidJUnit4::class)
class AppZygoteTimingRuntimeTest {
    @Test fun collectParentTimingTwice() = runBlocking(Dispatchers.IO) {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("requireAppZygoteTiming") == "true")
        val detector = DuckDetector.detectors.single { it.id.value == "selinux" }
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val scanner = detector.createScanner(context)
        repeat(2) {
            val report = scanner.scan() as? SelinuxReport
            assertNotNull("SELinux report missing", report)
            val reading = requireNotNull(report).methods
                .firstOrNull { it.oracle == SelinuxOracle.APP_ZYGOTE_ATTR_TIMING }?.avcLookup
            assertNotNull("App Zygote timing row missing", reading)
            val timing = requireNotNull(reading)
            assertTrue("Parent timing incomplete: ${timing.parentTiming}", timing.parentTiming.complete)
            assertEquals("Incomplete parent timing", 512, timing.parentTiming.pairs)
            assertEquals("Expected unpinned parent protocol", 1, timing.parentTiming.protocol)
            assertEquals("Parent moved CPUs", 0, timing.parentTiming.migrations)
            when (arguments.getString("expectedAppZygoteTiming")) {
                "negative" -> assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE, timing.timingVerdict)
                "positive" -> assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, timing.timingVerdict)
            }
        }
    }
}
