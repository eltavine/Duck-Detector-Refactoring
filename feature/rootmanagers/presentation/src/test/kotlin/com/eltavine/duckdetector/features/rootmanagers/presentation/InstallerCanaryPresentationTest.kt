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

package com.eltavine.duckdetector.features.rootmanagers.presentation

import com.eltavine.duckdetector.features.rootmanagers.domain.*
import org.junit.Assert.*
import org.junit.Test

class InstallerCanaryPresentationTest {
    @Test fun unknownUserAndDirectoryFailuresRemainVisibleInExport() {
        val observation = InstallerCanaryObservation(InstallerCanaryState.PERMISSION_OWNER_OBSERVED,
            "org.example.owner", directoryErrors = mapOf(2 to 999, 13 to 1))
        val model = RootManagersCardModelMapper().map(
            RootManagersReport.unavailable("Denied").copy(installerCanary = observation))
        assertEquals("Candidate permission owner observed", model.verdict)
        assertTrue(model.summary.contains("not established"))
        assertTrue(model.scanRows.any { it.label == "Owner directory coordinates" && it.value == "Not observable" })
        assertTrue(model.scanRows.any { it.hiddenCopyText?.contains("2=999") == true })
        assertTrue(model.toDetectorReport().toString().contains("org.example.owner"))
    }

    @Test fun permissionMissDoesNotBecomeClaimThatManagerIsAbsent() {
        val rows = installerCanaryRows(InstallerCanaryObservation(InstallerCanaryState.PERMISSION_NOT_OBSERVED))
        assertEquals("Permission conflict not observed", rows.first().value)
        assertTrue(rows.first().hiddenCopyText!!.contains("rebuilt permission may differ"))
    }
}
