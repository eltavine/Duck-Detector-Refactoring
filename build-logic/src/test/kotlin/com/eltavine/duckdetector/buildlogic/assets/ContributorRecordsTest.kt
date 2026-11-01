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

import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Test

class ContributorRecordsTest {

    private fun remote(login: String, contributions: Int) =
        GitHubContributor(login, login, "https://github.com/$login", "https://a/$login", contributions, codeVolume = 0)

    @Test
    fun `the manual contributor wins over GitHub's record of the same login`() {
        val records = contributorRecords(listOf(remote("SakanyaNotBot", 99)), recorded = emptyMap())
        val record = records.single { it.login == "SakanyaNotBot" }

        assertEquals(1, record.contributions)
        assertEquals("author_summary_wuying", record.summaryKey)
    }

    @Test
    fun `GitHub records keep their recorded keys and get sanitised avatar files`() {
        val records = contributorRecords(
            listOf(remote("Some.User", 3)),
            recorded = mapOf("Some.User" to ContributorMetadata("summary", listOf("tee"))),
        )
        val record = records.first { it.login == "Some.User" }

        assertEquals("some_user.jpg", record.avatarFileName)
        assertEquals("github_contributors/avatars/some_user.jpg", record.avatarAssetPath)
        assertEquals("summary", record.summaryKey)
        assertEquals(listOf("tee"), record.contributionKeys)
        assertEquals(listOf("Some.User", "SakanyaNotBot", "sinanb9"), records.map { it.login })
    }

    @Test
    fun `more than forty contributors keep metadata without duplicating manual entries`() {
        val contributors = (1..43).map { remote("contributor$it", it) } +
            listOf(remote("SakanyaNotBot", 1), remote("sinanb9", 1))
        val records = contributorRecords(
            contributors,
            recorded = mapOf("contributor43" to ContributorMetadata("summary", listOf("security"))),
        )

        assertEquals(45, records.size)
        assertEquals(45, records.map { it.login }.distinct().size)
        val record = records.single { it.login == "contributor43" }
        assertEquals("summary", record.summaryKey)
        assertEquals(listOf("security"), record.contributionKeys)
        assertEquals("无影", records.single { it.login == "SakanyaNotBot" }.name)
    }

    @Test
    fun `metadata that cannot be read is empty`() {
        val directory = Files.createTempDirectory("contributors").toFile()
        val invalid = directory.resolve("invalid.json").apply { writeText("not json") }

        assertEquals(emptyMap<String, ContributorMetadata>(), readRecordedMetadata(directory.resolve("missing.json")))
        assertEquals(emptyMap<String, ContributorMetadata>(), readRecordedMetadata(invalid))
    }
}
