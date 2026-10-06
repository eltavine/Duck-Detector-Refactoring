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

import android.text.format.Formatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.Android
import androidx.compose.material.icons.rounded.NewReleases
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Source
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.features.update.domain.AvailableUpdate
import io.github.xiaotong6666.uihelper.adaptive.WrapSafeText
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

/** What the update is, and the size and SHA-256 that let the user check the file they download. */
@Composable
internal fun UpdateMetadataRows(update: AvailableUpdate) {
    val manifest = update.manifest
    val release = manifest.release
    if (release != null) {
        UpdateMetadataRow(
            icon = Icons.Rounded.NewReleases,
            label = stringResource(R.string.update_release_label),
            value = "${release.tag} · ${manifest.commit.sha.take(SHORT_SHA_LENGTH)}",
            monospace = true,
        )
    } else {
        UpdateMetadataRow(
            icon = Icons.Rounded.Source,
            label = stringResource(R.string.update_branch_hash_label),
            value = "${manifest.branch} · ${manifest.commit.sha.take(SHORT_SHA_LENGTH)}",
            monospace = true,
        )
        UpdateMetadataRow(
            icon = Icons.Rounded.AccountCircle,
            label = stringResource(R.string.update_author_label),
            value = manifest.commit.authorName,
        )
    }
    UpdateMetadataRow(
        icon = Icons.Rounded.Schedule,
        label = stringResource(R.string.update_time_label),
        value = formatUpdateTime(manifest.builtAtUtc),
    )
    UpdateMetadataRow(
        icon = Icons.Rounded.Android,
        label = stringResource(R.string.update_apk_label),
        value = "${Formatter.formatFileSize(LocalContext.current, manifest.apk.sizeBytes)}\n${manifest.apk.sha256}",
        monospace = true,
        selectable = true,
    )
}

@Composable
private fun UpdateMetadataRow(
    icon: ImageVector,
    label: String,
    value: String,
    monospace: Boolean = false,
    selectable: Boolean = false,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerLarge,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 11.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp),
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                WrapSafeText(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                val valueText: @Composable () -> Unit = {
                    WrapSafeText(
                        text = value,
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = if (monospace) FontFamily.Monospace else null,
                        ),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
                if (selectable) {
                    SelectionContainer(content = valueText)
                } else {
                    valueText()
                }
            }
        }
    }
}

internal fun formatUpdateTime(raw: String): String {
    return runCatching {
        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM)
            .withLocale(Locale.getDefault())
            .withZone(ZoneId.systemDefault())
            .format(Instant.parse(raw))
    }.getOrDefault(raw)
}

internal const val SHORT_SHA_LENGTH = 8
