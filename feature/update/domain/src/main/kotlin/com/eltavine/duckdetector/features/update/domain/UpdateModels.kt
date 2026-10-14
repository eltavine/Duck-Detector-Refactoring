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

data class UpdateManifest(
    val schemaVersion: Int,
    val channel: UpdateChannel,
    val branch: String,
    val versionName: String,
    val versionCode: Int,
    val commit: UpdateCommit,
    val builtAtUtc: String,
    val apk: UpdateApk,
    /** The release a Stable manifest belongs to. Nightly manifests have none. */
    val release: UpdateRelease? = null,
    /** What main gained since the last stable release. Only Nightly manifests carry it. */
    val changes: UpdateChanges? = null,
)

data class UpdateCommit(
    val sha: String,
    val subject: String,
    val body: String,
    val authorName: String,
    val authoredAt: String,
)

data class UpdateApk(
    val name: String,
    val downloadUrl: String,
    val sizeBytes: Long,
    val sha256: String,
)

/** A stable release; [notes] is its changelog as GitHub generated it for the release page. */
data class UpdateRelease(
    val tag: String,
    val url: String,
    val notes: String,
)

/** The first-parent changes after [baseSha], newest first; [entries] holds the newest of [totalCount]. */
data class UpdateChanges(
    val baseTag: String?,
    val baseSha: String?,
    val totalCount: Int,
    val entries: List<UpdateChangelogEntry>,
)

data class UpdateChangelogEntry(
    val sha: String,
    val subject: String,
    val authorName: String,
    val pullRequest: Int? = null,
)

sealed interface UpdateChangelog {
    /** The changes a Nightly adds. [remainingCount] is null when earlier ones may be missing. */
    data class Commits(
        val entries: List<UpdateChangelogEntry>,
        val remainingCount: Int?,
    ) : UpdateChangelog

    /** A stable release's notes, read from the Markdown on its release page. */
    data class ReleaseNotes(
        val sections: List<ReleaseNotesSection>,
    ) : UpdateChangelog
}

data class ReleaseNotesSection(
    val title: String?,
    val items: List<ReleaseNotesItem>,
)

data class ReleaseNotesItem(
    val text: String,
    val author: String? = null,
    val pullRequest: Int? = null,
)

data class AvailableUpdate(
    val manifest: UpdateManifest,
    val changelog: UpdateChangelog,
    /** The manifest's GitHub download URL, or that URL through gh-proxy.com while acceleration is on. */
    val downloadUrl: String,
    /** GitHub's comparison with the running build for Nightly, the release page for Stable. */
    val changesUrl: String,
)

sealed interface UpdateCheckResult {
    data class Current(
        val manifest: UpdateManifest,
    ) : UpdateCheckResult

    /** The running build is newer than the channel's latest, as after moving from Nightly to Stable. */
    data class Ahead(
        val manifest: UpdateManifest,
    ) : UpdateCheckResult

    data class Available(
        val update: AvailableUpdate,
    ) : UpdateCheckResult
}
