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

package com.eltavine.duckdetector.ui

import com.eltavine.duckdetector.features.update.domain.UpdateInstallResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UpdateInstallFallbackTest {
    private val url = "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/test.apk"

    @Test
    fun `installer launch failure copies link and opens browser`() {
        val actions = mutableListOf<String>()
        val result = fallbackFromFailedLocalInstall(
            UpdateInstallResult.Failed, url,
            copy = { actions += "copy:$it"; true },
            open = { actions += "open:$it"; true },
        )
        assertEquals(UpdateInstallFallbackResult(true, true), result)
        assertEquals(listOf("copy:$url", "open:$url"), actions)
    }

    @Test
    fun `missing cached apk uses the same fallback route`() {
        val proxyUrl = "https://gh-proxy.com/$url"
        val used = mutableListOf<String>()
        val result = fallbackFromFailedLocalInstall(
            UpdateInstallResult.ApkUnavailable, proxyUrl,
            copy = { used += it; true },
            open = { used += it; true },
        )
        assertEquals(UpdateInstallFallbackResult(true, true), result)
        assertEquals(listOf(proxyUrl, proxyUrl), used)
    }

    @Test
    fun `clipboard failure does not stop browser`() {
        var browserCalls = 0
        val result = fallbackFromFailedLocalInstall(
            UpdateInstallResult.Failed, url,
            copy = { throw IllegalStateException("clipboard unavailable") },
            open = { browserCalls++; true },
        )
        assertEquals(UpdateInstallFallbackResult(false, true), result)
        assertEquals(1, browserCalls)
    }

    @Test
    fun `browser failure retains copied download link`() {
        var copyCalls = 0
        val result = fallbackFromFailedLocalInstall(
            UpdateInstallResult.Failed, url,
            copy = { copyCalls++; true },
            open = { throw IllegalStateException("no browser") },
        )
        assertEquals(UpdateInstallFallbackResult(true, false), result)
        assertEquals(1, copyCalls)
    }

    @Test
    fun `permission flow and launched installer never open fallback`() {
        for (result in listOf(UpdateInstallResult.PermissionRequired, UpdateInstallResult.Launched)) {
            assertNull(fallbackFromFailedLocalInstall(
                result, url,
                copy = { error("unexpected clipboard write") },
                open = { error("unexpected browser launch") },
            ))
        }
    }

    @Test
    fun `missing or non-https link invokes neither fallback action`() {
        for (link in listOf(null, "", "http://example.org/test.apk", "https://")) {
            val result = fallbackFromFailedLocalInstall(
                UpdateInstallResult.Failed, link,
                copy = { error("unexpected clipboard write") },
                open = { error("unexpected browser launch") },
            )
            assertEquals(UpdateInstallFallbackResult(false, false), result)
        }
    }
}
