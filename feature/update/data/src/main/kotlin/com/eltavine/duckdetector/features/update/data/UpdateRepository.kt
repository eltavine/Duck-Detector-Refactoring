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

import com.eltavine.duckdetector.features.update.domain.AvailableUpdate
import com.eltavine.duckdetector.features.update.domain.BuildStanding
import com.eltavine.duckdetector.features.update.domain.UpdateChangelog
import com.eltavine.duckdetector.features.update.domain.UpdateChangelogEntry
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import com.eltavine.duckdetector.features.update.domain.UpdateChecker
import com.eltavine.duckdetector.features.update.domain.UpdateManifest
import com.eltavine.duckdetector.features.update.domain.newerThan
import com.eltavine.duckdetector.features.update.domain.standingOf
import kotlin.math.ceil
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class UpdateRepository internal constructor(
    private val httpClient: UpdateHttpClient = HttpUrlConnectionUpdateClient(),
    private val cache: UpdateCompareCache,
    private val currentRoute: suspend () -> GitHubRoute,
    private val manifestParser: UpdateManifestParser = UpdateManifestParser(),
    private val compareParser: GitHubCompareParser = GitHubCompareParser(),
    private val releaseNotesParser: ReleaseNotesParser = ReleaseNotesParser(),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : UpdateChecker {

    override suspend fun check(
        channel: UpdateChannel,
        currentVersionCode: Int,
        currentCommitSha: String,
    ): UpdateCheckResult = withContext(ioDispatcher) {
        val route = currentRoute()
        val manifestJson = httpClient.get(route.url(UpdateEndpoints.manifestUrl(channel)), JSON_ACCEPT)
        val manifest = manifestParser.parse(manifestJson, channel)
        when (standingOf(manifest, currentVersionCode, currentCommitSha)) {
            BuildStanding.CURRENT -> UpdateCheckResult.Current(manifest)
            BuildStanding.AHEAD -> UpdateCheckResult.Ahead(manifest)
            BuildStanding.BEHIND -> UpdateCheckResult.Available(
                update = buildAvailableUpdate(manifest, currentCommitSha, route),
            )
        }
    }

    private suspend fun buildAvailableUpdate(
        manifest: UpdateManifest,
        currentCommitSha: String,
        route: GitHubRoute,
    ): AvailableUpdate {
        val release = manifest.release
        return AvailableUpdate(
            manifest = manifest,
            changelog = if (release != null) {
                UpdateChangelog.ReleaseNotes(releaseNotesParser.parse(release.notes))
            } else {
                nightlyChangelog(manifest, currentCommitSha, route)
            },
            downloadUrl = route.url(manifest.apk.downloadUrl),
            changesUrl = release?.url ?: buildCompareWebUrl(currentCommitSha, manifest.commit.sha),
        )
    }

    /**
     * The manifest's own list answers for any build since the last stable release without another
     * request, gh-proxy.com included. Older or unrelated builds fall back to GitHub's comparison,
     * and then to the newest listed changes, flagged as possibly incomplete.
     */
    private suspend fun nightlyChangelog(
        manifest: UpdateManifest,
        currentCommitSha: String,
        route: GitHubRoute,
    ): UpdateChangelog.Commits {
        manifest.changes?.newerThan(currentCommitSha)?.let { listed ->
            val visible = listed.entries.take(MAX_VISIBLE_COMMITS)
            return UpdateChangelog.Commits(
                entries = visible,
                remainingCount = listed.remainingCount?.let { it + listed.entries.size - visible.size },
            )
        }

        val comparePage = try {
            loadComparePage(currentCommitSha, manifest.commit.sha, route)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            null
        }
        val compared = comparePage?.commits.orEmpty().asReversed().take(MAX_VISIBLE_COMMITS)
        if (comparePage != null && compared.isNotEmpty()) {
            val totalCommits = comparePage.totalCommits.coerceAtLeast(compared.size)
            return UpdateChangelog.Commits(entries = compared, remainingCount = totalCommits - compared.size)
        }

        val listed = manifest.changes?.entries.orEmpty().take(MAX_VISIBLE_COMMITS)
        return UpdateChangelog.Commits(
            entries = listed.ifEmpty {
                listOf(
                    UpdateChangelogEntry(
                        sha = manifest.commit.sha,
                        subject = manifest.commit.subject,
                        authorName = manifest.commit.authorName,
                    ),
                )
            },
            remainingCount = null,
        )
    }

    private suspend fun loadComparePage(
        baseSha: String,
        headSha: String,
        route: GitHubRoute,
    ): GitHubComparePage {
        if (!COMPARABLE_SHA_REGEX.matches(baseSha) || !COMPARABLE_SHA_REGEX.matches(headSha)) {
            throw IllegalArgumentException("Commit SHA cannot be compared through GitHub.")
        }
        val cacheKey = "${baseSha.lowercase()}...${headSha.lowercase()}"
        readCachedCompare(cacheKey)?.let { cachedJson ->
            runCatching { compareParser.parse(cachedJson) }
                .getOrNull()
                ?.let { return it }
        }
        if (!route.comparesCommits) {
            throw UnsupportedOperationException("Commits cannot be compared through $route.")
        }

        val firstPageJson = httpClient.get(
            route.url(buildCompareApiUrl(baseSha, headSha, page = 1)),
            GITHUB_JSON_ACCEPT,
        )
        val firstPage = compareParser.parse(firstPageJson)
        val selectedJson = if (firstPage.totalCommits > COMPARE_PAGE_SIZE) {
            val lastPage = ceil(firstPage.totalCommits.toDouble() / COMPARE_PAGE_SIZE).toInt()
            httpClient.get(
                route.url(buildCompareApiUrl(baseSha, headSha, page = lastPage)),
                GITHUB_JSON_ACCEPT,
            )
        } else {
            firstPageJson
        }
        writeCachedCompare(cacheKey, selectedJson)
        return compareParser.parse(selectedJson)
    }

    private suspend fun readCachedCompare(cacheKey: String): String? {
        return try {
            cache.read(cacheKey)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun writeCachedCompare(cacheKey: String, json: String) {
        try {
            cache.write(cacheKey, json)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            // Changelog caching is optional and must not suppress a valid update result.
        }
    }

    private fun buildCompareApiUrl(baseSha: String, headSha: String, page: Int): String {
        return "${UpdateEndpoints.API_REPOSITORY}/compare/$baseSha...$headSha" +
            "?per_page=$COMPARE_PAGE_SIZE&page=$page"
    }

    private fun buildCompareWebUrl(baseSha: String, headSha: String): String {
        return "${UpdateEndpoints.WEB_REPOSITORY}/compare/$baseSha...$headSha"
    }

    private companion object {
        private const val JSON_ACCEPT = "application/json"
        private const val GITHUB_JSON_ACCEPT = "application/vnd.github+json"
        private const val COMPARE_PAGE_SIZE = 100
        private const val MAX_VISIBLE_COMMITS = 10
        private val COMPARABLE_SHA_REGEX = Regex("^[0-9a-fA-F]{7,40}$")
    }
}
