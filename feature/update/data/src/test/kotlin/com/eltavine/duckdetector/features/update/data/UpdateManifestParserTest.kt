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

package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class UpdateManifestParserTest {
    private val parser = UpdateManifestParser()

    @Test
    fun `parses a valid legacy master Nightly manifest`() {
        val manifest = parser.parse(validUpdateManifestJson(), UpdateChannel.NIGHTLY)

        assertEquals(1, manifest.schemaVersion)
        assertEquals(UpdateChannel.NIGHTLY, manifest.channel)
        assertEquals("master", manifest.branch)
        assertEquals(TEST_HEAD_SHA, manifest.commit.sha)
        assertEquals(500, manifest.versionCode)
        assertEquals("Duck.Detector-test.apk", manifest.apk.name)
        assertNull(manifest.release)
        assertNull(manifest.changes)
    }

    @Test
    fun `parses a valid main Nightly manifest`() {
        val manifest = parser.parse(validUpdateManifestJson(branch = "main"), UpdateChannel.NIGHTLY)

        assertEquals("main", manifest.branch)
    }

    @Test
    fun `rejects an unexpected Nightly branch`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(validUpdateManifestJson(branch = "development"), UpdateChannel.NIGHTLY)
        }
    }

    @Test
    fun `rejects a manifest of the other channel`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(validUpdateManifestJson(), UpdateChannel.STABLE)
        }
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(validStableManifestJson(), UpdateChannel.NIGHTLY)
        }
    }

    @Test
    fun `rejects unsupported schema`() {
        val json = JSONObject(validUpdateManifestJson())
            .put("schemaVersion", 2)
            .toString()

        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(json, UpdateChannel.NIGHTLY)
        }
    }

    @Test
    fun `rejects an invalid build timestamp`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(validUpdateManifestJson(builtAtUtc = "2026-08-08 12:30"), UpdateChannel.NIGHTLY)
        }
    }

    @Test
    fun `rejects download URLs outside the official Nightly release`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(
                validUpdateManifestJson(downloadUrl = "https://example.com/Duck.Detector-test.apk"),
                UpdateChannel.NIGHTLY,
            )
        }
    }

    @Test
    fun `rejects a mismatched APK filename`() {
        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(
                validUpdateManifestJson(
                    downloadUrl =
                        "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/another.apk",
                ),
                UpdateChannel.NIGHTLY,
            )
        }
    }

    @Test
    fun `rejects numeric values encoded as strings`() {
        val json = JSONObject(validUpdateManifestJson())
            .put("versionCode", "500")
            .toString()

        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(json, UpdateChannel.NIGHTLY)
        }
    }

    @Test
    fun `rejects unsafe APK asset names`() {
        val json = JSONObject(validUpdateManifestJson())
        json.getJSONObject("apk")
            .put("name", "../Duck.Detector-test.apk")

        assertThrows(UpdateManifestValidationException::class.java) {
            parser.parse(json.toString(), UpdateChannel.NIGHTLY)
        }
    }

    @Test
    fun `parses Nightly changes since the last stable release`() {
        val changes = changesJson(listOf(testSha(2), testSha(1)), totalCount = 5)
        val manifest = parser.parse(validUpdateManifestJson(changes = changes), UpdateChannel.NIGHTLY)

        val parsed = requireNotNull(manifest.changes)
        assertEquals(TEST_STABLE_TAG, parsed.baseTag)
        assertEquals(TEST_BASE_SHA, parsed.baseSha)
        assertEquals(5, parsed.totalCount)
        assertEquals(listOf(testSha(2), testSha(1)), parsed.entries.map { it.sha })
        assertEquals(listOf(100, null), parsed.entries.map { it.pullRequest })
    }

    @Test
    fun `invalid Nightly changes are dropped without rejecting the update`() {
        val broken = listOf(
            changesJson(listOf(testSha(1)), totalCount = 0),
            changesJson(listOf("not-a-sha")),
            changesJson(listOf(testSha(1)), baseTag = "nightly"),
            changesJson(listOf(testSha(1)), baseSha = null),
        )

        broken.forEach { changes ->
            val manifest = parser.parse(validUpdateManifestJson(changes = changes), UpdateChannel.NIGHTLY)
            assertNull(manifest.changes)
        }
    }

    @Test
    fun `parses a stable manifest with its release notes`() {
        val manifest = parser.parse(validStableManifestJson(), UpdateChannel.STABLE)

        assertEquals(UpdateChannel.STABLE, manifest.channel)
        assertEquals("26.10.0", manifest.versionName)
        val release = requireNotNull(manifest.release)
        assertEquals(TEST_STABLE_TAG, release.tag)
        assertEquals(TEST_RELEASE_URL, release.url)
        assertEquals(TEST_RELEASE_NOTES, release.notes)
        assertNull(manifest.changes)
    }

    @Test
    fun `rejects stable manifests that do not match their release`() {
        val invalid = listOf(
            validStableManifestJson(versionName = "26.10.1"),
            validStableManifestJson(tag = "v26.13.0", versionName = "26.13.0"),
            validStableManifestJson(releaseUrl = "https://example.com/releases/tag/v26.10.0"),
            validStableManifestJson(downloadUrl = TEST_DOWNLOAD_URL),
            validStableManifestJson(
                downloadUrl =
                    "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/v26.9.0/Duck.Detector-26.10.0.apk",
            ),
            JSONObject(validStableManifestJson()).apply { remove("release") }.toString(),
        )

        invalid.forEach { json ->
            assertThrows(UpdateManifestValidationException::class.java) {
                parser.parse(json, UpdateChannel.STABLE)
            }
        }
    }
}
