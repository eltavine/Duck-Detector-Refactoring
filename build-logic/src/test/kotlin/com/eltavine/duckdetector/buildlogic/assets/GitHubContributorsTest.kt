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

import org.gradle.api.GradleException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class GitHubContributorsTest {

    private val feed = """
        [
          {"total": 5, "weeks": [{"a": 1, "d": 1}], "author": {"login": "bob", "path": "/bob", "avatar": "https://a/b?s=60&v=4"}},
          {"total": 9, "weeks": [], "author": {"login": "amy", "avatar": "https://a/a"}},
          {"total": 5, "weeks": [{"a": 10, "d": 0}], "author": {"login": "Cid", "path": "/Cid"}}
        ]
    """

    @Test
    fun `contributors come in contribution, then changed line, then login order`() {
        val contributors = parseGitHubContributors(feed)

        assertEquals(listOf("amy", "Cid", "bob"), contributors.map { it.login })
        assertEquals(listOf(9, 5, 5), contributors.map { it.contributions })
        assertEquals(listOf(0, 10, 2), contributors.map { it.codeVolume })
    }

    @Test
    fun `contributors beyond the first thirty are all retained`() {
        val feed = (1..45).joinToString(prefix = "[", postfix = "]") { index ->
            """{"total": $index, "author": {"login": "contributor$index"}}"""
        }

        val contributors = parseGitHubContributors(feed)

        assertEquals(45, contributors.size)
        assertEquals((45 downTo 1).map { "contributor$it" }, contributors.map { it.login })
    }

    @Test
    fun `profile urls come from the author path, avatars are requested at 512 pixels`() {
        val byLogin = parseGitHubContributors(feed).associateBy { it.login }

        assertEquals("https://github.com/bob", byLogin.getValue("bob").profileUrl)
        assertEquals("https://github.com/amy", byLogin.getValue("amy").profileUrl)
        assertEquals("https://a/b?s=512&v=4", byLogin.getValue("bob").avatarUrl)
        assertEquals("https://a/a?s=512", byLogin.getValue("amy").avatarUrl)
        assertEquals(null, byLogin.getValue("Cid").avatarUrl)
    }

    @Test
    fun `malformed feeds are rejected`() {
        listOf("{}", "[]", "[1]", "[{\"total\": 1}]", "[{\"author\": {\"login\": \"x\"}}]").forEach { body ->
            assertThrows(body, GradleException::class.java) { parseGitHubContributors(body) }
        }
    }

    @Test
    fun `the contributors page and avatars get different headers, and a token authorises both`() {
        val page = githubRequestHeaders(GITHUB_CONTRIBUTORS_API_URL, token = "secret")
        val avatar = githubRequestHeaders("https://avatars.githubusercontent.com/u/1", token = " ")

        assertEquals("application/json", page["Accept"])
        assertEquals("Bearer secret", page["Authorization"])
        assertEquals("application/vnd.github+json", avatar["Accept"])
        assertEquals("2022-11-28", avatar["X-GitHub-Api-Version"])
        assertEquals(null, avatar["Authorization"])
    }
}
