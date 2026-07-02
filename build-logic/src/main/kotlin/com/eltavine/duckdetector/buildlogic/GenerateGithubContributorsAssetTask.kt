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

package com.eltavine.duckdetector.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

internal const val GITHUB_CONTRIBUTORS_ASSET_FILE_NAME = "github_contributors.json"
internal const val GITHUB_CONTRIBUTORS_AVATAR_DIRECTORY = "github_contributors/avatars"
internal const val GITHUB_CONTRIBUTORS_API_URL =
    "https://github.com/eltavine/Duck-Detector-Refactoring/graphs/contributors-data"

abstract class GenerateGithubContributorsAssetTask : DefaultTask() {

    init {
        outputs.upToDateWhen { false }
    }

    @get:Input
    abstract val endpointUrl: Property<String>

    @get:Optional
    @get:Input
    abstract val authToken: Property<String>

    @get:Input
    abstract val maxAttempts: Property<Int>

    @get:Input
    abstract val connectTimeoutMillis: Property<Int>

    @get:Input
    abstract val readTimeoutMillis: Property<Int>

    @get:OutputFile
    abstract val contributorsAssetFile: RegularFileProperty

    @get:OutputDirectory
    abstract val avatarOutputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val contributorsFile = contributorsAssetFile.get().asFile
        contributorsFile.parentFile?.mkdirs()
        val avatarDirectory = avatarOutputDirectory.get().asFile.apply { mkdirs() }

        runCatching { fetchRemoteSnapshot(contributorsFile, avatarDirectory) }
            .onFailure { failure ->
                logger.warn(
                    "GitHub contributors sync failed; falling back to local asset: " +
                        (failure.message ?: failure.javaClass.simpleName)
                )
            }
            .getOrThrowUnlessRecoverable()
    }

    private fun fetchRemoteSnapshot(
        contributorsFile: java.io.File,
        avatarDirectory: java.io.File,
    ) {
        val existingMetadata = readExistingMetadata(contributorsFile)
        val contributors = fetchContributorsWithRetries()
        val payload = JSONArray()
        val expectedAvatarFiles = linkedSetOf<String>()

        contributors.forEach { contributor ->
            val assetFileName = sanitizeAssetFileName(contributor.login) + ".jpg"
            val assetPath = "$GITHUB_CONTRIBUTORS_AVATAR_DIRECTORY/$assetFileName"
            expectedAvatarFiles += assetFileName
            contributor.avatarUrl?.let { avatarUrl ->
                val avatarBytes = fetchBytes(avatarUrl)
                avatarDirectory.resolve(assetFileName).writeBytes(avatarBytes)
            }
            val metadata = existingMetadata[contributor.login]
            payload.put(
                JSONObject()
                    .put("login", contributor.login)
                    .put("name", contributor.name)
                    .put("profileUrl", contributor.profileUrl)
                    .put("avatarAssetPath", contributor.avatarUrl?.let { assetPath })
                    .put("contributions", contributor.contributions)
                    .put("summaryKey", metadata?.summaryKey)
                    .put("contributionKeys", JSONArray(metadata?.contributionKeys ?: emptyList<String>()))
            )
        }

        avatarDirectory.listFiles().orEmpty()
            .filter { it.isFile && it.name !in expectedAvatarFiles }
            .forEach { it.delete() }

        contributorsFile.writeText(payload.toString(2), Charsets.UTF_8)
    }

    private fun fetchContributorsWithRetries(): List<GitHubContributor> {
        val attempts = maxAttempts.get().coerceAtLeast(1)
        var lastFailure: Throwable? = null
        repeat(attempts) { index ->
            val attempt = index + 1
            val result = runCatching { fetchContributors() }
            val contributors = result.getOrNull()
            if (contributors != null) {
                logger.lifecycle(
                    "Fetched GitHub contributors from ${endpointUrl.get()} on attempt $attempt/$attempts."
                )
                return contributors
            }

            lastFailure = result.exceptionOrNull()
            logger.warn(
                "GitHub contributors fetch attempt $attempt/$attempts failed: " +
                    "${lastFailure?.message ?: lastFailure?.javaClass?.simpleName.orEmpty()}"
            )
            if (attempt < attempts) {
                Thread.sleep((300L * attempt).coerceAtMost(1_500L))
            }
        }

        throw GradleException(
            "GitHub contributors sync failed after $attempts attempts.",
            lastFailure,
        )
    }

    private fun fetchContributors(): List<GitHubContributor> {
        val body = fetchText(endpointUrl.get())
        val array = try {
            JSONArray(body)
        } catch (exception: JSONException) {
            throw GradleException("GitHub contributors payload is not a JSON array.", exception)
        }
        if (array.length() == 0) {
            throw GradleException("GitHub contributors payload is empty.")
        }
        return buildList(array.length()) {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index)
                    ?: throw GradleException("GitHub contributors item #$index is not a JSON object.")
                val author = item.optJSONObject("author")
                    ?: throw GradleException("GitHub contributors item #$index is missing author.")
                val login = author.optString("login").trim()
                val profileUrl = author.optString("path").trim().ifBlank { null }?.let { path ->
                    "https://github.com$path"
                } ?: "https://github.com/$login"
                val avatarUrl = author.optString("avatar").trim().ifBlank { null }?.let(::upgradeAvatarUrl)
                val contributions = item.optInt("total", -1)
                val codeVolume = item.optJSONArray("weeks").sumCodeVolume()
                if (login.isEmpty() || contributions < 0) {
                    throw GradleException("GitHub contributors item #$index is missing required fields.")
                }
                add(
                    GitHubContributor(
                        login = login,
                        name = login,
                        profileUrl = profileUrl,
                        avatarUrl = avatarUrl,
                        contributions = contributions,
                        codeVolume = codeVolume,
                    )
                )
            }
        }.sortedWith(
            compareByDescending<GitHubContributor> { it.contributions }
                .thenByDescending { it.codeVolume }
                .thenBy { it.login.lowercase() }
        )
    }

    private fun fetchText(url: String): String {
        return fetchConnection(url) { connection, statusCode ->
            val body = readBody(connection, statusCode)
            if (statusCode !in 200..299) {
                throw IOException("HTTP $statusCode ${connection.responseMessage.orEmpty()}".trim())
            }
            body
        }
    }

    private fun fetchBytes(url: String): ByteArray {
        return fetchConnection(url) { connection, statusCode ->
            if (statusCode !in 200..299) {
                val body = readBody(connection, statusCode)
                throw IOException(
                    "HTTP $statusCode ${connection.responseMessage.orEmpty()} ${body.take(120)}".trim()
                )
            }
            connection.inputStream.use { stream -> stream.readBytes() }
        }
    }

    private fun <T> fetchConnection(url: String, block: (HttpURLConnection, Int) -> T): T {
        val connection = URL(url).openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.connectTimeout = connectTimeoutMillis.get()
            connection.readTimeout = readTimeoutMillis.get()
            connection.instanceFollowRedirects = true
            if (url.lowercase(Locale.ROOT).contains("/graphs/contributors-data")) {
                connection.setRequestProperty(
                    "User-Agent",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0"
                )
                connection.setRequestProperty("Accept", "application/json")
            } else {
                connection.setRequestProperty("User-Agent", "Duck-Detector-Refactoring-Gradle")
                connection.setRequestProperty("Accept", "application/vnd.github+json")
                connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            }
            authToken.orNull?.takeIf(String::isNotBlank)?.let { token ->
                connection.setRequestProperty("Authorization", "Bearer $token")
            }
            block(connection, connection.responseCode)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBody(connection: HttpURLConnection, statusCode: Int): String {
        return (if (statusCode in 200..299) connection.inputStream else connection.errorStream)
            ?.bufferedReader(Charsets.UTF_8)
            ?.use { reader -> reader.readText() }
            .orEmpty()
    }

    private fun sanitizeAssetFileName(login: String): String {
        return buildString(login.length) {
            login.forEach { character ->
                append(
                    when {
                        character.isLetterOrDigit() -> character.lowercaseChar()
                        character == '-' || character == '_' -> character
                        else -> '_'
                    }
                )
            }
        }
    }

    private fun readExistingMetadata(file: java.io.File): Map<String, ContributorMetadata> {
        if (!file.isFile) {
            return emptyMap()
        }
        val payload = file.readText(Charsets.UTF_8)
        val array = try {
            JSONArray(payload)
        } catch (_: JSONException) {
            return emptyMap()
        }
        return buildMap {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val login = item.optString("login").trim()
                if (login.isBlank()) {
                    continue
                }
                put(
                    login,
                    ContributorMetadata(
                        summaryKey = item.optString("summaryKey").trim().ifBlank { null },
                        contributionKeys = item.optJSONArray("contributionKeys").toStringList(),
                    )
                )
            }
        }
    }
}

private fun Result<Unit>.getOrThrowUnlessRecoverable() {
    exceptionOrNull()?.let { failure ->
        if (failure is GradleException || failure is IOException) {
            return
        }
        throw failure
    }
}

private data class GitHubContributor(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarUrl: String?,
    val contributions: Int,
    val codeVolume: Int,
)

private data class ContributorMetadata(
    val summaryKey: String?,
    val contributionKeys: List<String>,
)

private fun JSONArray?.sumCodeVolume(): Int {
    if (this == null) {
        return 0
    }
    var total = 0
    for (index in 0 until length()) {
        val item = optJSONObject(index) ?: continue
        total += item.optInt("a", 0)
        total += item.optInt("d", 0)
    }
    return total
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return buildList(length()) {
        for (index in 0 until length()) {
            val value = optString(index).trim()
            if (value.isNotEmpty()) {
                add(value)
            }
        }
    }
}

private fun upgradeAvatarUrl(url: String): String {
    val sized = Regex("([?&])s=\\d+").replace(url, "$1s=512")
    return if (sized == url) {
        if ('?' in url) "$url&s=512" else "$url?s=512"
    } else {
        sized
    }
}
