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

package com.eltavine.duckdetector.features.update.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerTest {

    @Test
    fun `version codes order builds of either channel`() {
        val manifest = manifest(versionCode = 985, sha = sha('a'))

        assertEquals(BuildStanding.BEHIND, standingOf(manifest, 980, sha('b')))
        assertEquals(BuildStanding.AHEAD, standingOf(manifest, 990, sha('b')))
        assertEquals(BuildStanding.CURRENT, standingOf(manifest, 985, sha('b')))
    }

    @Test
    fun `a build of the manifest's commit is current whatever its version code`() {
        val manifest = manifest(versionCode = 985, sha = sha('a'))

        assertEquals(BuildStanding.CURRENT, standingOf(manifest, 900, sha('a').take(12).uppercase()))
    }

    @Test
    fun `abbreviations must be hexadecimal and at least seven characters`() {
        assertTrue(isSameCommit(sha('a'), "aaaaaaa"))
        assertFalse(isSameCommit(sha('a'), "aaaaaa"))
        assertFalse(isSameCommit(sha('a'), "unknown"))
        assertFalse(isSameCommit(sha('a'), ""))
    }

    @Test
    fun `changes after a listed build are the entries before it`() {
        val changes = changes(entries = listOf(sha('3'), sha('2'), sha('1')), totalCount = 3)

        val newer = changes.newerThan(sha('2').take(12))

        assertEquals(listOf(sha('3')), newer?.entries?.map { it.sha })
        assertEquals(0, newer?.remainingCount)
        assertEquals(emptyList<String>(), changes.newerThan(sha('3'))?.entries?.map { it.sha })
    }

    @Test
    fun `a build of the base lacks every change, listed or not`() {
        val changes = changes(entries = listOf(sha('3'), sha('2')), totalCount = 7)

        val newer = changes.newerThan(sha('b').take(12))

        assertEquals(2, newer?.entries?.size)
        assertEquals(5, newer?.remainingCount)
    }

    @Test
    fun `other builds cannot be placed in the list`() {
        val changes = changes(entries = listOf(sha('3')), totalCount = 1)

        assertNull(changes.newerThan(sha('e')))
        assertNull(changes.copy(baseTag = null, baseSha = null).newerThan(sha('b')))
    }

    private fun sha(character: Char): String = character.toString().repeat(40)

    private fun changes(entries: List<String>, totalCount: Int) = UpdateChanges(
        baseTag = "v26.10.0",
        baseSha = sha('b'),
        totalCount = totalCount,
        entries = entries.map { UpdateChangelogEntry(sha = it, subject = "Change $it", authorName = "Duck") },
    )

    private fun manifest(versionCode: Int, sha: String) = UpdateManifest(
        schemaVersion = 1,
        channel = UpdateChannel.STABLE,
        branch = "main",
        versionName = "26.10.0",
        versionCode = versionCode,
        commit = UpdateCommit(sha, "feat: ship", "", "Duck", "2026-10-01T08:00:00Z"),
        builtAtUtc = "2026-10-01T08:30:00Z",
        apk = UpdateApk("Duck.Detector-26.10.0.apk", "https://github.com/x", 1, "c".repeat(64)),
    )
}
