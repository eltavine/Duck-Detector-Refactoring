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
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.SystemUpdate
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.eltavine.duckdetector.features.update.domain.AvailableUpdate
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import io.github.xiaotong6666.uihelper.adaptive.WrapSafeText
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode

/**
 * The waiting update in the dialog of the current UI style. The MIUIX dialog keeps showing [update]
 * while it animates out after [show] turns false, and reports the end through [onDismissFinished].
 */
@Composable
fun UpdateDialog(
    show: Boolean,
    currentVersionName: String,
    update: AvailableUpdate,
    downloadEnabled: Boolean,
    onDismiss: () -> Unit,
    onViewChanges: () -> Unit,
    onDownload: () -> Unit,
    onDismissFinished: () -> Unit = {},
) {
    val stable = update.manifest.channel == UpdateChannel.STABLE
    val content = UpdateDialogContent(
        title = stringResource(if (stable) R.string.update_dialog_title_stable else R.string.update_dialog_title),
        versionChange = stringResource(
            R.string.update_version_change,
            currentVersionName,
            update.manifest.versionName,
        ),
        details = updateDetails(update),
        changelog = changelogView(update.changelog),
        viewChangesLabel = stringResource(if (stable) R.string.update_view_release else R.string.update_view_changes),
    )
    when (LocalUiMode.current) {
        UiMode.Miuix -> UpdateDialogMiuix(
            show = show,
            content = content,
            downloadEnabled = downloadEnabled,
            onDismiss = onDismiss,
            onViewChanges = onViewChanges,
            onDownload = onDownload,
            onDismissFinished = onDismissFinished,
        )

        UiMode.Material -> if (show) {
            UpdateDialogMaterial(
                content = content,
                downloadEnabled = downloadEnabled,
                onDismiss = onDismiss,
                onViewChanges = onViewChanges,
                onDownload = onDownload,
            )
        }
    }
}

/** What both dialog styles show of an update. */
internal class UpdateDialogContent(
    val title: String,
    val versionChange: String,
    val details: List<UpdateDetail>,
    val changelog: ChangelogView?,
    val viewChangesLabel: String,
)

@Composable
private fun UpdateDialogMaterial(
    content: UpdateDialogContent,
    downloadEnabled: Boolean,
    onDismiss: () -> Unit,
    onViewChanges: () -> Unit,
    onDownload: () -> Unit,
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp),
            contentAlignment = Alignment.Center,
        ) {
            Surface(
                modifier = Modifier
                    .widthIn(max = 560.dp)
                    .heightIn(max = 680.dp),
                shape = MaterialTheme.shapes.extraLarge,
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 22.dp, vertical = 20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    UpdateDialogHeaderMaterial(title = content.title, versionChange = content.versionChange)

                    Column(
                        modifier = Modifier
                            .weight(1f, fill = false)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(14.dp),
                    ) {
                        UpdateDetailsMaterial(details = content.details)
                        content.changelog?.let { changelog -> UpdateChangelogMaterial(changelog) }
                    }

                    TextButton(
                        onClick = onViewChanges,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp),
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp),
                        )
                        WrapSafeText(
                            text = content.viewChangesLabel,
                            modifier = Modifier.padding(start = 8.dp),
                            style = MaterialTheme.typography.labelLarge,
                        )
                    }
                    UpdateDialogActionsMaterial(
                        downloadEnabled = downloadEnabled,
                        onDismiss = onDismiss,
                        onDownload = onDownload,
                    )
                }
            }
        }
    }
}

@Composable
private fun UpdateDialogHeaderMaterial(title: String, versionChange: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.primaryContainer,
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .padding(12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.SystemUpdate,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = title,
                style = MaterialTheme.typography.titleLargeEmphasized,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = versionChange,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun UpdateDialogActionsMaterial(
    downloadEnabled: Boolean,
    onDismiss: () -> Unit,
    onDownload: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TextButton(
            onClick = onDismiss,
            modifier = Modifier
                .weight(1f)
                .heightIn(min = 48.dp),
        ) {
            WrapSafeText(
                text = stringResource(R.string.update_later),
                style = MaterialTheme.typography.labelLarge,
            )
        }
        Button(
            onClick = onDownload,
            enabled = downloadEnabled,
            modifier = Modifier
                .weight(1.5f)
                .heightIn(min = 48.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.Download,
                contentDescription = null,
                modifier = Modifier.size(18.dp),
            )
            WrapSafeText(
                text = stringResource(R.string.update_download),
                modifier = Modifier.padding(start = 8.dp),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}
