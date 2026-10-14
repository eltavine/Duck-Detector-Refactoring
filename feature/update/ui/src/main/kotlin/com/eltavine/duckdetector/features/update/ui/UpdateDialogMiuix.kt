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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIcon
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.HorizontalDivider
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog

/**
 * The MIUIX form of [UpdateDialog]. It follows uihelper's UpdatePromptDialog, which cannot show
 * release-note sections or a selectable SHA-256, and keeps the actions below the scrolling details.
 */
@Composable
internal fun UpdateDialogMiuix(
    show: Boolean,
    content: UpdateDialogContent,
    downloadEnabled: Boolean,
    onDismiss: () -> Unit,
    onViewChanges: () -> Unit,
    onDownload: () -> Unit,
    onDismissFinished: () -> Unit,
) {
    WindowDialog(
        show = show,
        modifier = Modifier.windowInsetsPadding(WindowInsets.systemBars.only(WindowInsetsSides.Top)),
        title = content.title,
        summary = content.versionChange,
        onDismissRequest = onDismiss,
        onDismissFinished = onDismissFinished,
    ) {
        Layout(
            content = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    UpdateDetailsMiuix(details = content.details)
                    content.changelog?.let { changelog -> UpdateChangelogMiuix(changelog) }
                    TextButton(
                        text = content.viewChangesLabel,
                        onClick = onViewChanges,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TextButton(
                        text = stringResource(R.string.update_later),
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f),
                    )
                    Spacer(Modifier.width(16.dp))
                    TextButton(
                        text = stringResource(R.string.update_download),
                        onClick = onDownload,
                        enabled = downloadEnabled,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                    )
                }
            },
        ) { measurables, constraints ->
            // The actions are measured first, so long notes scroll while the actions stay visible.
            val actions = measurables[1].measure(constraints.copy(minHeight = 0))
            val details = measurables[0].measure(
                constraints.copy(
                    minHeight = 0,
                    maxHeight = (constraints.maxHeight - actions.height).coerceAtLeast(0),
                ),
            )
            layout(constraints.maxWidth, details.height + actions.height) {
                details.place(0, 0)
                actions.place(0, details.height)
            }
        }
    }
}

@Composable
private fun UpdateDetailsMiuix(details: List<UpdateDetail>) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        insideMargin = PaddingValues(horizontal = 14.dp, vertical = 4.dp),
    ) {
        details.forEachIndexed { index, detail ->
            UpdateDetailRowMiuix(detail)
            if (index != details.lastIndex) {
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun UpdateDetailRowMiuix(detail: UpdateDetail) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        AdaptiveIcon(
            imageVector = detail.icon,
            contentDescription = null,
            modifier = Modifier.size(20.dp),
            tint = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            Text(
                text = detail.label,
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
            // Not truncated: the SHA-256 is only useful in full.
            SelectableValue(selectable = detail.selectable) {
                Text(
                    text = detail.value,
                    style = MiuixTheme.textStyles.body2.copy(
                        fontFamily = if (detail.monospace) FontFamily.Monospace else null,
                    ),
                    color = MiuixTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

@Composable
private fun UpdateChangelogMiuix(changelog: ChangelogView) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            text = changelog.heading,
            style = MiuixTheme.textStyles.headline1,
            color = MiuixTheme.colorScheme.onSurface,
        )
        changelog.groups.forEach { group ->
            group.title?.let { title ->
                Text(
                    text = title,
                    modifier = Modifier.padding(top = 4.dp),
                    style = MiuixTheme.textStyles.headline2,
                    color = MiuixTheme.colorScheme.onSurface,
                )
            }
            group.lines.forEach { line ->
                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text(
                        text = line.text,
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurface,
                    )
                    line.detail?.let { detail ->
                        Text(
                            text = detail,
                            style = MiuixTheme.textStyles.footnote1.copy(
                                fontFamily = if (line.monospaceDetail) FontFamily.Monospace else null,
                            ),
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                    }
                }
            }
        }
        changelog.footnote?.let { footnote ->
            Text(
                text = footnote,
                style = MiuixTheme.textStyles.footnote1,
                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}
