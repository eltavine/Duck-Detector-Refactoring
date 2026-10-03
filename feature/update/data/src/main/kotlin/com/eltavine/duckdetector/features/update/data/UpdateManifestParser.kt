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

import com.eltavine.duckdetector.features.update.domain.UpdateApk
import com.eltavine.duckdetector.features.update.domain.UpdateChangelogEntry
import com.eltavine.duckdetector.features.update.domain.UpdateChanges
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.domain.UpdateCommit
import com.eltavine.duckdetector.features.update.domain.UpdateManifest
import com.eltavine.duckdetector.features.update.domain.UpdateRelease
import java.net.URI
import org.json.JSONObject

/**
 * Reads update.json as .github/scripts/release_manifest.py writes it. A Stable manifest must name
 * its release, and its APK must be an asset of that release; a Nightly APK must be an asset of the
 * Nightly release.
 */
class UpdateManifestParser {

    fun parse(rawJson: String, expectedChannel: UpdateChannel): UpdateManifest {
        val root = runCatching { JSONObject(rawJson) }
            .getOrElse { throw UpdateManifestValidationException("Update manifest is not valid JSON.") }
        val schemaVersion = root.requirePositiveInt("schemaVersion")
        if (schemaVersion != SUPPORTED_SCHEMA_VERSION) {
            throw UpdateManifestValidationException("Unsupported update manifest schema: $schemaVersion")
        }

        val channelId = root.requireNonBlankString("channel")
        if (UpdateChannel.fromId(channelId) != expectedChannel) {
            throw UpdateManifestValidationException("Unexpected update channel: $channelId")
        }
        val branch = root.requireNonBlankString("branch")
        if (branch !in EXPECTED_BRANCHES) {
            throw UpdateManifestValidationException("Unexpected update branch: $branch")
        }

        val versionName = root.requireNonBlankString("versionName")
        val release = when (expectedChannel) {
            UpdateChannel.STABLE -> parseRelease(root.requireObject("release"), versionName)
            UpdateChannel.NIGHTLY -> null
        }
        return UpdateManifest(
            schemaVersion = schemaVersion,
            channel = expectedChannel,
            branch = branch,
            versionName = versionName,
            versionCode = root.requirePositiveInt("versionCode"),
            commit = parseCommit(root.requireObject("commit")),
            builtAtUtc = root.requireIsoInstant("builtAtUtc"),
            apk = parseApk(root.requireObject("apk"), releaseTag = release?.tag ?: UpdateEndpoints.NIGHTLY_TAG),
            release = release,
            changes = if (expectedChannel == UpdateChannel.NIGHTLY) parseOptionalChanges(root) else null,
        )
    }

    private fun parseCommit(json: JSONObject): UpdateCommit {
        val sha = json.requireNonBlankString("sha").lowercase()
        if (!FULL_SHA_REGEX.matches(sha)) {
            throw UpdateManifestValidationException("Update commit SHA must contain 40 hexadecimal characters.")
        }
        return UpdateCommit(
            sha = sha,
            subject = json.requireNonBlankString("subject"),
            body = json.optionalString("body"),
            authorName = json.requireNonBlankString("authorName"),
            authoredAt = json.requireIsoInstant("authoredAt"),
        )
    }

    private fun parseRelease(json: JSONObject, versionName: String): UpdateRelease {
        val tag = json.requireNonBlankString("tag")
        if (!STABLE_TAG_REGEX.matches(tag) || versionName != tag.removePrefix("v")) {
            throw UpdateManifestValidationException("Stable release $tag does not name version $versionName.")
        }
        val url = json.requireNonBlankString("url")
        if (url != "${UpdateEndpoints.WEB_REPOSITORY}/releases/tag/$tag") {
            throw UpdateManifestValidationException("Release URL is outside the repository's releases.")
        }
        return UpdateRelease(tag = tag, url = url, notes = json.optionalString("notes"))
    }

    private fun parseApk(json: JSONObject, releaseTag: String): UpdateApk {
        val name = json.requireNonBlankString("name")
        if (name.length > MAX_ASSET_NAME_LENGTH ||
            !name.endsWith(".apk", ignoreCase = true) ||
            name.any { it == '/' || it == '\\' || it.isISOControl() }
        ) {
            throw UpdateManifestValidationException("Update asset name is invalid.")
        }
        val downloadUrl = json.requireNonBlankString("downloadUrl")
        validateDownloadUrl(downloadUrl, name, releaseTag)
        val sha256 = json.requireNonBlankString("sha256").lowercase()
        if (!SHA256_REGEX.matches(sha256)) {
            throw UpdateManifestValidationException("APK SHA-256 is invalid.")
        }
        return UpdateApk(
            name = name,
            downloadUrl = downloadUrl,
            sizeBytes = json.requirePositiveLong("sizeBytes"),
            sha256 = sha256,
        )
    }

    private fun validateDownloadUrl(rawUrl: String, apkName: String, releaseTag: String) {
        val uri = runCatching { URI(rawUrl) }
            .getOrElse { throw UpdateManifestValidationException("APK download URL is invalid.") }
        if (uri.scheme != "https" ||
            !uri.host.equals(EXPECTED_DOWNLOAD_HOST, ignoreCase = true) ||
            uri.rawUserInfo != null ||
            uri.port != -1
        ) {
            throw UpdateManifestValidationException("APK download URL must use the official GitHub host.")
        }
        if (uri.path != "${UpdateEndpoints.REPOSITORY_PATH}/releases/download/$releaseTag/$apkName") {
            throw UpdateManifestValidationException("APK download URL is outside the $releaseTag release.")
        }
    }

    // The changes only list what an update adds. A list that fails validation is dropped rather than
    // failing the check, and the repository compares the builds through GitHub instead.
    private fun parseOptionalChanges(root: JSONObject): UpdateChanges? {
        val json = root.optJSONObject("changes") ?: return null
        return try {
            parseChanges(json)
        } catch (_: UpdateManifestValidationException) {
            null
        }
    }

    private fun parseChanges(json: JSONObject): UpdateChanges {
        val baseTag = json.nullableString("baseTag")
        val baseSha = json.nullableString("baseSha")?.lowercase()
        if ((baseTag == null) != (baseSha == null) ||
            (baseTag != null && !STABLE_TAG_REGEX.matches(baseTag)) ||
            (baseSha != null && !FULL_SHA_REGEX.matches(baseSha))
        ) {
            throw UpdateManifestValidationException("Changes name an invalid base release.")
        }
        val entriesJson = json.optJSONArray("entries")
            ?: throw UpdateManifestValidationException("Changes have no entries.")
        val entries = (0 until entriesJson.length()).map { index ->
            val entry = entriesJson.optJSONObject(index)
                ?: throw UpdateManifestValidationException("Change entry $index is not an object.")
            val sha = entry.requireNonBlankString("sha").lowercase()
            if (!FULL_SHA_REGEX.matches(sha)) {
                throw UpdateManifestValidationException("Change entry $index has an invalid SHA.")
            }
            UpdateChangelogEntry(
                sha = sha,
                subject = entry.requireNonBlankString("subject"),
                authorName = entry.optionalString("authorName").trim(),
                pullRequest = if (entry.isNull("pullRequest")) null else entry.requirePositiveInt("pullRequest"),
            )
        }
        val totalCount = json.requireNonNegativeInt("totalCount")
        if (totalCount < entries.size) {
            throw UpdateManifestValidationException("Changes count fewer changes than they list.")
        }
        return UpdateChanges(baseTag = baseTag, baseSha = baseSha, totalCount = totalCount, entries = entries)
    }

    private companion object {
        private const val SUPPORTED_SCHEMA_VERSION = 1
        private val EXPECTED_BRANCHES = setOf("main", "master")
        private const val EXPECTED_DOWNLOAD_HOST = "github.com"
        private const val MAX_ASSET_NAME_LENGTH = 255
        private val FULL_SHA_REGEX = Regex("^[0-9a-f]{40}$")
        private val SHA256_REGEX = Regex("^[0-9a-f]{64}$")
        private val STABLE_TAG_REGEX = Regex("""^v\d{2}\.(?:[1-9]|1[0-2])\.(?:0|[1-9]\d*)$""")
    }
}
