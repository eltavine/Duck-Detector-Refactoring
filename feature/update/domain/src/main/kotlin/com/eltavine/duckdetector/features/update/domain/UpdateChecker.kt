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

fun interface UpdateChecker {
    suspend fun check(
        channel: UpdateChannel,
        currentVersionCode: Int,
        currentCommitSha: String,
    ): UpdateCheckResult
}

enum class BuildStanding {
    CURRENT,
    BEHIND,
    AHEAD,
}

/**
 * Both channels build main and number a build by the commits behind it, so versionCode orders a
 * Stable and a Nightly build as it orders two of either. A build of the manifest's own commit is
 * current whatever its channel.
 */
fun standingOf(
    manifest: UpdateManifest,
    currentVersionCode: Int,
    currentCommitSha: String,
): BuildStanding = when {
    isSameCommit(manifest.commit.sha, currentCommitSha) -> BuildStanding.CURRENT
    manifest.versionCode > currentVersionCode -> BuildStanding.BEHIND
    manifest.versionCode < currentVersionCode -> BuildStanding.AHEAD
    else -> BuildStanding.CURRENT
}

/** [abbreviatedSha] may be shortened, as BuildConfig.BUILD_HASH is to 12 characters. */
fun isSameCommit(fullSha: String, abbreviatedSha: String): Boolean {
    val candidate = abbreviatedSha.lowercase()
    return ABBREVIATED_SHA.matches(candidate) && fullSha.lowercase().startsWith(candidate)
}

/**
 * The changes after the running build. The list names every first-parent commit since the last
 * stable release, so a build found in it lacks exactly the entries before it, and a build of the
 * base lacks all of them. Any other build, such as one older than the base, gets null: the list
 * cannot say what it lacks.
 */
fun UpdateChanges.newerThan(currentCommitSha: String): UpdateChangelog.Commits? {
    val index = entries.indexOfFirst { entry -> isSameCommit(entry.sha, currentCommitSha) }
    return when {
        index >= 0 -> UpdateChangelog.Commits(entries = entries.take(index), remainingCount = 0)
        baseSha != null && isSameCommit(baseSha, currentCommitSha) -> UpdateChangelog.Commits(
            entries = entries,
            remainingCount = (totalCount - entries.size).coerceAtLeast(0),
        )
        else -> null
    }
}

private val ABBREVIATED_SHA = Regex("[0-9a-f]{7,40}")
