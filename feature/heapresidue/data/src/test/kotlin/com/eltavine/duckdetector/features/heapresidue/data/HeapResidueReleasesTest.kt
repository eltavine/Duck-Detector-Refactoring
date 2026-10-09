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

package com.eltavine.duckdetector.features.heapresidue.data

import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueRelease
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HeapResidueReleasesTest {
    @Test fun releasesBeforeAndroid12AreNotRunEvenAsPreviews() {
        for (api in listOf(29, 30)) for (prerelease in listOf(false, true)) {
            assertNull(HeapResidueReleases.classify(api, prerelease))
        }
    }

    @Test fun android12To17AreAuditedBaselines() {
        for (api in 31..37) assertEquals(HeapResidueRelease.AUDITED, HeapResidueReleases.classify(api, prerelease = false))
    }

    @Test fun newerReleasesRunButAreNeverReportedAsAudited() {
        for (api in listOf(38, 39, 50)) assertEquals(HeapResidueRelease.NEWER, HeapResidueReleases.classify(api, prerelease = false))
    }

    @Test fun previewReportingAnAuditedApiLevelIsNotAudited() {
        for (api in listOf(31, 36, 37, 38)) {
            assertEquals(HeapResidueRelease.PRERELEASE, HeapResidueReleases.classify(api, prerelease = true))
        }
    }
}
