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

package com.eltavine.duckdetector.features.licenses.data

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AboutLibrariesJsonOverridesTest {
    @Test
    fun apply_rewritesSoterLicenseMetadata() {
        val input = """
            {
              "libraries": [
                {
                  "uniqueId": "com.github.Tencent.soter:soter-wrapper",
                  "name": "Tencent/soter",
                  "description": "Original",
                  "website": "https://github.com/Tencent/soter",
                  "licenses": ["other"]
                }
              ],
              "licenses": {
                "BSD-3-Clause": {
                  "name": "BSD 3-Clause"
                }
              }
            }
        """.trimIndent()

        val updated = JSONObject(AboutLibrariesJsonOverrides.apply(input))
        val library = updated.getJSONArray("libraries").getJSONObject(0)

        assertEquals("Tencent Soter", library.getString("name"))
        assertEquals(
            "https://github.com/Tencent/soter/blob/master/LICENSE",
            library.getString("website"),
        )
        assertEquals("BSD-3-Clause", library.getJSONArray("licenses").getString(0))
        assertTrue(library.getString("description").contains("BSD 3-Clause"))
    }

    @Test
    fun apply_rewritesHiddenApiBypassLicenseMetadata() {
        val input = """
            {
              "libraries": [
                {
                  "uniqueId": "org.lsposed.hiddenapibypass:hiddenapibypass",
                  "name": "hiddenapibypass",
                  "description": "Original",
                  "website": "https://github.com/LSPosed/AndroidHiddenApiBypass",
                  "licenses": ["other"]
                }
              ],
              "licenses": {
                "Apache-2.0": {
                  "name": "Apache License 2.0"
                }
              }
            }
        """.trimIndent()

        val updated = JSONObject(AboutLibrariesJsonOverrides.apply(input))
        val library = updated.getJSONArray("libraries").getJSONObject(0)

        assertEquals("Android HiddenApiBypass", library.getString("name"))
        assertEquals(
            "https://github.com/LSPosed/AndroidHiddenApiBypass/blob/main/LICENSE",
            library.getString("website"),
        )
        assertEquals("Apache-2.0", library.getJSONArray("licenses").getString(0))
        assertTrue(library.getString("description").contains("Apache License 2.0"))
    }

    @Test
    fun apply_updatesKnownVersionsAndProjectLinks() {
        val input = """
            {
              "libraries": [
                {
                  "uniqueId": "com.mikepenz:aboutlibraries-compose-m3",
                  "artifactVersion": "13.2.1",
                  "name": "AboutLibraries Compose Material 3 Library",
                  "website": "https://github.com/mikepenz/AboutLibraries"
                },
                {
                  "uniqueId": "org.bouncycastle:bcprov-jdk18on",
                  "artifactVersion": "1.83",
                  "name": "Bouncy Castle Provider",
                  "description": "Old BC description"
                },
                {
                  "uniqueId": "com.google.android.datatransport:transport-runtime",
                  "artifactVersion": "3.3.0",
                  "name": "transport-runtime",
                  "description": "",
                  "website": ""
                }
              ]
            }
        """.trimIndent()

        val updated = JSONObject(AboutLibrariesJsonOverrides.apply(input))
        val libraries = updated.getJSONArray("libraries")

        assertEquals(
            "14.0.0",
            libraries.getJSONObject(0).getString("artifactVersion"),
        )
        assertEquals(
            "1.84",
            libraries.getJSONObject(1).getString("artifactVersion"),
        )
        assertTrue(
            libraries.getJSONObject(1).getString("description").contains("version 1.84"),
        )
        assertEquals(
            "https://github.com/firebase/firebase-android-sdk",
            libraries.getJSONObject(2).getString("website"),
        )
    }
}
