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

import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SrcuTimingApplicabilityTest {
    @Test fun `public API presence does not make Android 15 persistence a packages list trigger`() {
        for (api in listOf(29, 35, 36, 37)) {
            assertEquals(SrcuTimingCollection.UNSUPPORTED_ANDROID, srcuTimingApplicability(api, "6.12.81-android16"))
        }
    }
    @Test fun `only reviewed kernel families pass the structural gate`() {
        for (release in listOf("5.10.240-android12", "5.15.200", "6.1.140", "6.6.90", "6.12.81")) {
            assertNull(srcuTimingApplicability(34, release))
        }
        for (release in listOf("5.4.100", "6.8.0", "unknown", "999999999999.1")) {
            assertEquals(SrcuTimingCollection.UNSUPPORTED_KERNEL, srcuTimingApplicability(34, release))
        }
    }
}
