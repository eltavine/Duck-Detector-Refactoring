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

import com.eltavine.duckdetector.features.update.domain.UpdateChangelog
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateRepositoryTest {

    @Test
    fun `same remote version is current and a lower one leaves the build ahead`() = runBlocking {
        val urls = mutableListOf<String>()
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                urls += url
                validUpdateManifestJson(versionCode = 500)
            },
        )

        val same = repository.check(UpdateChannel.NIGHTLY, currentVersionCode = 500, currentCommitSha = TEST_BASE_SHA)
        val lower = repository.check(UpdateChannel.NIGHTLY, currentVersionCode = 501, currentCommitSha = TEST_BASE_SHA)

        assertTrue(same is UpdateCheckResult.Current)
        assertTrue(lower is UpdateCheckResult.Ahead)
        assertEquals(listOf(UpdateEndpoints.NIGHTLY_MANIFEST_URL, UpdateEndpoints.NIGHTLY_MANIFEST_URL), urls)
    }

    @Test
    fun `same remote SHA is current even when version code is higher`() = runBlocking {
        val repository = repository(
            client = UpdateHttpClient { _, _ -> validUpdateManifestJson(versionCode = 500) },
        )

        val full = repository.check(UpdateChannel.NIGHTLY, currentVersionCode = 400, currentCommitSha = TEST_HEAD_SHA)
        val abbreviated = repository.check(UpdateChannel.NIGHTLY, 400, TEST_HEAD_SHA.take(12))

        assertTrue(full is UpdateCheckResult.Current)
        assertTrue(abbreviated is UpdateCheckResult.Current)
    }

    @Test
    fun `comparison is newest first filtered and limited to ten commits`() = runBlocking {
        val commits = (1..12).map { index -> testCommit(index, isMerge = index == 11) }
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                if (url == UpdateEndpoints.NIGHTLY_MANIFEST_URL) {
                    validUpdateManifestJson()
                } else {
                    compareResponseJson(totalCommits = 12, commits = commits)
                }
            },
        )

        val changelog = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA))

        assertEquals(10, changelog.entries.size)
        assertEquals("Commit 12", changelog.entries.first().subject)
        assertFalse(changelog.entries.any { it.subject == "Commit 11" })
        assertEquals(2, changelog.remainingCount)
    }

    @Test
    fun `cached comparison avoids another GitHub API request`() = runBlocking {
        val cache = FakeUpdateCompareCache()
        val cacheKey = "${TEST_BASE_SHA.lowercase()}...${TEST_HEAD_SHA.lowercase()}"
        cache.values[cacheKey] = compareResponseJson(1, listOf(testCommit(1)))
        val urls = mutableListOf<String>()
        val repository = repository(
            cache = cache,
            client = UpdateHttpClient { url, _ ->
                urls += url
                validUpdateManifestJson()
            },
        )

        val changelog = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA))

        assertEquals("Commit 1", changelog.entries.single().subject)
        assertEquals(listOf(UpdateEndpoints.NIGHTLY_MANIFEST_URL), urls)
    }

    @Test
    fun `large comparisons fetch the final page`() = runBlocking {
        val urls = mutableListOf<String>()
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                urls += url
                when {
                    url == UpdateEndpoints.NIGHTLY_MANIFEST_URL -> validUpdateManifestJson()
                    "&page=1" in url -> compareResponseJson(101, emptyList())
                    else -> compareResponseJson(101, listOf(testCommit(101)))
                }
            },
        )

        val changelog = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA))

        assertTrue(urls.any { "&page=2" in it })
        assertEquals("Commit 101", changelog.entries.single().subject)
        assertEquals(100, changelog.remainingCount)
    }

    @Test
    fun `comparison failure falls back to manifest commit message`() = runBlocking {
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                if (url == UpdateEndpoints.NIGHTLY_MANIFEST_URL) {
                    validUpdateManifestJson()
                } else {
                    throw IOException("rate limited")
                }
            },
        )

        val changelog = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA))

        assertEquals("feat(update): publish Nightly metadata", changelog.entries.single().subject)
        assertNull(changelog.remainingCount)
    }

    @Test
    fun `cache write failure does not suppress an available update`() = runBlocking {
        val failingCache = object : UpdateCompareCache {
            override suspend fun read(key: String): String? = null

            override suspend fun write(key: String, json: String) {
                throw IOException("disk unavailable")
            }
        }
        val repository = repository(
            cache = failingCache,
            client = UpdateHttpClient { url, _ ->
                if (url == UpdateEndpoints.NIGHTLY_MANIFEST_URL) {
                    validUpdateManifestJson()
                } else {
                    compareResponseJson(1, listOf(testCommit(1)))
                }
            },
        )

        val result = repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA)

        assertTrue(result is UpdateCheckResult.Available)
    }

    @Test
    fun `direct check opens the manifest download URL`() = runBlocking {
        val repository = repository(
            client = UpdateHttpClient { url, _ ->
                if (url == UpdateEndpoints.NIGHTLY_MANIFEST_URL) {
                    validUpdateManifestJson()
                } else {
                    compareResponseJson(1, listOf(testCommit(1)))
                }
            },
        )

        val result = repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA) as UpdateCheckResult.Available

        assertEquals(TEST_DOWNLOAD_URL, result.update.downloadUrl)
    }

    @Test
    fun `accelerated check goes through gh-proxy without comparing commits`() = runBlocking {
        val urls = mutableListOf<String>()
        val repository = repository(
            route = GitHubRoute.GH_PROXY,
            client = UpdateHttpClient { url, _ ->
                urls += url
                validUpdateManifestJson()
            },
        )

        val result = repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA) as UpdateCheckResult.Available
        val changelog = result.update.changelog as UpdateChangelog.Commits

        assertEquals(listOf("https://gh-proxy.com/${UpdateEndpoints.NIGHTLY_MANIFEST_URL}"), urls)
        assertEquals("https://gh-proxy.com/$TEST_DOWNLOAD_URL", result.update.downloadUrl)
        assertEquals("feat(update): publish Nightly metadata", changelog.entries.single().subject)
        assertNull(changelog.remainingCount)
        assertTrue(result.update.changesUrl.startsWith("https://github.com/"))
    }

    @Test
    fun `accelerated check still lists a cached comparison`() = runBlocking {
        val cache = FakeUpdateCompareCache()
        val cacheKey = "${TEST_BASE_SHA.lowercase()}...${TEST_HEAD_SHA.lowercase()}"
        cache.values[cacheKey] = compareResponseJson(2, listOf(testCommit(1), testCommit(2)))
        val repository = repository(
            cache = cache,
            route = GitHubRoute.GH_PROXY,
            client = UpdateHttpClient { _, _ -> validUpdateManifestJson() },
        )

        val changelog = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA))

        assertEquals(listOf("Commit 2", "Commit 1"), changelog.entries.map { it.subject })
        assertEquals(0, changelog.remainingCount)
    }

    @Test
    fun `listed changes name what a newer Nightly adds without a comparison`() = runBlocking {
        val listed = (12 downTo 1).map(::testSha)
        val urls = mutableListOf<String>()
        val repository = repository(
            route = GitHubRoute.GH_PROXY,
            client = UpdateHttpClient { url, _ ->
                urls += url
                validUpdateManifestJson(changes = changesJson(listed, totalCount = 30))
            },
        )

        val fromListedBuild = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, testSha(3).take(12)))
        val fromBase = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, TEST_BASE_SHA.take(12)))

        assertEquals((12 downTo 4).map(::testSha), fromListedBuild.entries.map { it.sha })
        assertEquals(0, fromListedBuild.remainingCount)
        assertEquals(10, fromBase.entries.size)
        assertEquals(20, fromBase.remainingCount)
        assertEquals(2, urls.size)
    }

    @Test
    fun `a build missing from the listed changes still gets them, flagged as incomplete`() = runBlocking {
        val repository = repository(
            route = GitHubRoute.GH_PROXY,
            client = UpdateHttpClient { _, _ ->
                validUpdateManifestJson(changes = changesJson(listOf(testSha(2), testSha(1)), totalCount = 2))
            },
        )

        val changelog = nightlyChangelog(repository.check(UpdateChannel.NIGHTLY, 400, "c".repeat(12)))

        assertEquals(listOf(testSha(2), testSha(1)), changelog.entries.map { it.sha })
        assertNull(changelog.remainingCount)
    }

    @Test
    fun `stable check reads the latest release and its notes`() = runBlocking {
        val urls = mutableListOf<String>()
        val repository = repository(
            route = GitHubRoute.GH_PROXY,
            client = UpdateHttpClient { url, _ ->
                urls += url
                validStableManifestJson()
            },
        )

        val result = repository.check(UpdateChannel.STABLE, 400, TEST_BASE_SHA) as UpdateCheckResult.Available
        val notes = result.update.changelog as UpdateChangelog.ReleaseNotes

        assertEquals(listOf("https://gh-proxy.com/${UpdateEndpoints.STABLE_MANIFEST_URL}"), urls)
        assertEquals("https://gh-proxy.com/$TEST_STABLE_DOWNLOAD_URL", result.update.downloadUrl)
        assertEquals(TEST_RELEASE_URL, result.update.changesUrl)
        assertEquals(listOf("What's Changed", "New Contributors"), notes.sections.map { it.title })
        assertEquals(151, notes.sections.first().items.first().pullRequest)
    }

    @Test
    fun `a Nightly build newer than the latest Stable is ahead of it`() = runBlocking {
        val repository = repository(
            client = UpdateHttpClient { _, _ -> validStableManifestJson(versionCode = 985) },
        )

        val result = repository.check(UpdateChannel.STABLE, 990, TEST_BASE_SHA)

        assertEquals("26.10.0", (result as UpdateCheckResult.Ahead).manifest.versionName)
    }

    private fun nightlyChangelog(result: UpdateCheckResult): UpdateChangelog.Commits =
        (result as UpdateCheckResult.Available).update.changelog as UpdateChangelog.Commits

    private fun repository(
        client: UpdateHttpClient,
        cache: UpdateCompareCache = FakeUpdateCompareCache(),
        route: GitHubRoute = GitHubRoute.DIRECT,
    ): UpdateRepository {
        return UpdateRepository(
            httpClient = client,
            cache = cache,
            currentRoute = { route },
            ioDispatcher = Dispatchers.Unconfined,
        )
    }
}

private class FakeUpdateCompareCache : UpdateCompareCache {
    val values = mutableMapOf<String, String>()

    override suspend fun read(key: String): String? = values[key]

    override suspend fun write(key: String, json: String) {
        values[key] = json
    }
}
