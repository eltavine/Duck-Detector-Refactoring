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

package com.eltavine.duckdetector.buildlogic.assets

import java.net.URI
import org.gradle.api.GradleException
import org.json.JSONArray
import org.json.JSONException

internal const val GITHUB_CONTRIBUTORS_API_URL =
    "https://api.github.com/repos/eltavine/Duck-Detector-Refactoring/stats/contributors"

/** One contributor in GitHub's repository statistics API. */
internal data class GitHubContributor(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarUrl: String?,
    val contributions: Int,
    val codeVolume: Int,
)

/** Parses GitHub's repository statistics API, most contributions and then most changed lines first. */
internal fun parseGitHubContributors(body: String): List<GitHubContributor> {
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
            val profileUrl = author.optString("html_url").trim().ifBlank { "https://github.com/$login" }
            val avatarUrl = author.optString("avatar_url").trim().ifBlank { null }?.let(::upgradeAvatarUrl)
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

/** Credentials belong only to the API origin, never to contributor-supplied avatar URLs. */
internal fun githubRequestHeaders(url: String, token: String?): Map<String, String> = buildMap {
    put("User-Agent", "Duck-Detector-Refactoring-Gradle")
    val uri = URI.create(url)
    if (uri.scheme == "https" && uri.host.equals("api.github.com", ignoreCase = true) &&
        (uri.port == -1 || uri.port == 443)
    ) {
        put("Accept", "application/vnd.github+json")
        put("X-GitHub-Api-Version", "2022-11-28")
        token?.takeIf(String::isNotBlank)?.let { put("Authorization", "Bearer $it") }
    }
}

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

private fun upgradeAvatarUrl(url: String): String {
    val sized = Regex("([?&])s=\\d+").replace(url, "$1s=512")
    return if (sized == url) {
        if ('?' in url) "$url&s=512" else "$url?s=512"
    } else {
        sized
    }
}
