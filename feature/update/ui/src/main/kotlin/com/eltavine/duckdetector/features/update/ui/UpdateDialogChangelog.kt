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

package com.eltavine.duckdetector.features.update.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.features.update.domain.ReleaseNotesItem
import com.eltavine.duckdetector.features.update.domain.UpdateChangelog
import io.github.xiaotong6666.uihelper.adaptive.WrapSafeText

// The release page keeps the full notes; the dialog shows enough to decide on the update.
private const val MAX_RELEASE_NOTE_ITEMS = 40

@Composable
internal fun UpdateChangelogSection(changelog: UpdateChangelog) {
    when (changelog) {
        is UpdateChangelog.Commits -> CommitChangelog(changelog)
        is UpdateChangelog.ReleaseNotes -> ReleaseNotesChangelog(changelog)
    }
}

@Composable
private fun CommitChangelog(changelog: UpdateChangelog.Commits) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        ChangelogHeading(stringResource(R.string.update_changelog_title))
        changelog.entries.forEach { entry ->
            ChangelogBullet(
                text = entry.subject,
                detail = listOfNotNull(entry.sha.take(SHORT_SHA_LENGTH), entry.pullRequest?.let { "#$it" })
                    .joinToString(DETAIL_SEPARATOR),
                monospaceDetail = true,
            )
        }
        val remainingCount = changelog.remainingCount
        val remaining = when {
            remainingCount == null -> stringResource(R.string.update_remaining_commits_unknown)
            remainingCount > 0 -> pluralStringResource(
                R.plurals.update_remaining_commits,
                remainingCount,
                remainingCount,
            )
            else -> null
        }
        if (remaining != null) {
            ChangelogFootnote(remaining)
        }
    }
}

@Composable
private fun ReleaseNotesChangelog(changelog: UpdateChangelog.ReleaseNotes) {
    if (changelog.sections.isEmpty()) {
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        ChangelogHeading(stringResource(R.string.update_release_notes_title))
        var shown = 0
        changelog.sections.forEach { section ->
            val items = section.items.take((MAX_RELEASE_NOTE_ITEMS - shown).coerceAtLeast(0))
            if (items.isEmpty()) {
                return@forEach
            }
            section.title?.let { title ->
                WrapSafeText(
                    text = title,
                    modifier = Modifier.padding(top = 4.dp),
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            items.forEach { item -> ChangelogBullet(text = item.text, detail = item.detail()) }
            shown += items.size
        }
        val hidden = changelog.sections.sumOf { it.items.size } - shown
        if (hidden > 0) {
            ChangelogFootnote(pluralStringResource(R.plurals.update_release_notes_more, hidden, hidden))
        }
    }
}

private fun ReleaseNotesItem.detail(): String? =
    listOfNotNull(author?.let { "@$it" }, pullRequest?.let { "#$it" })
        .joinToString(DETAIL_SEPARATOR)
        .ifEmpty { null }

@Composable
private fun ChangelogHeading(text: String) {
    WrapSafeText(
        text = text,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
private fun ChangelogBullet(text: String, detail: String?, monospaceDetail: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Box(
            modifier = Modifier
                .padding(top = 7.dp)
                .size(7.dp)
                .background(color = MaterialTheme.colorScheme.primary, shape = CircleShape),
        )
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (detail != null) {
                WrapSafeText(
                    text = detail,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = if (monospaceDetail) FontFamily.Monospace else null,
                    ),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun ChangelogFootnote(text: String) {
    WrapSafeText(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

private const val DETAIL_SEPARATOR = " · "
