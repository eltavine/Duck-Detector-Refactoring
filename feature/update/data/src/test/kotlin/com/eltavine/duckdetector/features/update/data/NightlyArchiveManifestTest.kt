/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NightlyArchiveManifestTest {
    private val tag = "nightly-2026-08-08-${TEST_HEAD_SHA.take(8)}"
    private val archiveUrl = TEST_DOWNLOAD_URL.replace("/nightly/", "/$tag/")
    private fun parse(rawJson: String) = UpdateManifestParser().parse(rawJson, UpdateChannel.NIGHTLY)

    private fun channel(): JSONObject = JSONObject(validUpdateManifestJson()).apply {
        put("releaseTag", "nightly")
        put("archive", JSONObject().put("tag", tag).put("apk",
            JSONObject(getJSONObject("apk").toString()).put("downloadUrl", archiveUrl)))
    }

    @Test
    fun `fixed channel retains legacy fields while the new parser selects its archive`() {
        val json = channel()
        assertEquals(TEST_DOWNLOAD_URL, json.getJSONObject("apk").getString("downloadUrl"))
        val parsed = parse(json.toString())
        assertEquals(archiveUrl, parsed.apk.downloadUrl)
        assertEquals(parse(validUpdateManifestJson()).apk.copy(downloadUrl = archiveUrl), parsed.apk)
    }

    @Test
    fun `manifests without archive metadata remain supported`() {
        assertEquals(TEST_DOWNLOAD_URL, parse(validUpdateManifestJson()).apk.downloadUrl)
    }

    @Test
    fun `standalone archive validates the full commit and UTC build date`() {
        val json = JSONObject(validUpdateManifestJson(downloadUrl = archiveUrl)).put("releaseTag", tag)
        assertEquals(archiveUrl, parse(json.toString()).apk.downloadUrl)
        for (badTag in listOf("nightly-2026-02-30-aaaaaaaa", "nightly-2026-08-09-aaaaaaaa",
                             "nightly-2026-08-08-bbbbbbbb")) {
            json.getJSONObject("apk").put("downloadUrl", archiveUrl.replace(tag, badTag))
            json.put("releaseTag", badTag)
            assertThrows(UpdateManifestValidationException::class.java) { parse(json.toString()) }
        }
    }

    @Test
    fun `archive bytes must agree with the legacy channel metadata`() {
        val mutations = listOf<(JSONObject) -> Unit>(
            { it.getJSONObject("archive").getJSONObject("apk").put("sizeBytes", 1) },
            { it.getJSONObject("archive").getJSONObject("apk").put("sha256", "d".repeat(64)) },
            { it.getJSONObject("archive").getJSONObject("apk").put("name", "another.apk") },
            { it.getJSONObject("archive").put("tag", "nightly") },
            { it.put("archive", JSONObject.NULL) },
            { it.getJSONObject("archive").getJSONObject("apk").put("downloadUrl", "https://evil.example/file.apk") },
        )
        for (mutate in mutations) {
            val json = channel().also(mutate)
            assertThrows(UpdateManifestValidationException::class.java) { parse(json.toString()) }
        }
    }

    @Test
    fun `independent verification reads the selected archive instead of the rolling channel`() {
        val requests = mutableListOf<String>()
        val expected = parse(channel().toString()).apk
        val source = NightlyManifestSource(UpdateHttpClient { url, _ ->
            requests += url
            JSONObject(validUpdateManifestJson(downloadUrl = archiveUrl)).put("releaseTag", tag).toString()
        })
        assertEquals(expected, source.forApk(expected))
        assertEquals(listOf(NightlyReleasePaths.manifestUrl(tag)), requests)
    }

    @Test
    fun `untrusted asset URLs fail before requesting metadata`() {
        var requests = 0
        val source = NightlyManifestSource(UpdateHttpClient { _, _ -> requests++; error("unexpected request") })
        val apk = parse(validUpdateManifestJson()).apk.copy(downloadUrl = "https://evil.example/build.apk")
        assertThrows(IllegalArgumentException::class.java) { source.forApk(apk) }
        assertEquals(0, requests)
    }

    @Test
    fun `unrelated releases and decorated URLs are rejected`() {
        for (url in listOf(
            TEST_DOWNLOAD_URL.replace("Duck-Detector-Refactoring", "another-repository"),
            "$TEST_DOWNLOAD_URL?redirect=elsewhere", "$TEST_DOWNLOAD_URL#fragment",
            TEST_DOWNLOAD_URL.replace("github.com", "github.com:443"),
        )) {
            assertThrows(UpdateManifestValidationException::class.java) {
                parse(validUpdateManifestJson(downloadUrl = url))
            }
        }
    }
}
