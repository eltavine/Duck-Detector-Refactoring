/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.features.settings.ui.components

import android.content.ClipData
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Email
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.ui.theme.ShapeTokens

private const val ABOUT_WEBSITE = "eltavine.com"
private const val ABOUT_EMAIL = "me@eltavine.com"
private const val ABOUT_GITHUB_URL = "https://github.com/eltavine/Duck-Detector-Refactoring"
private const val ABOUT_GITHUB_REPOSITORY = "eltavine/Duck-Detector-Refactoring"

@Composable
fun AboutCard(
    versionName: String,
    versionCode: Int,
    buildTimeUtc: String,
    buildHash: String,
    modifier: Modifier = Modifier,
) {
    val uriHandler = LocalUriHandler.current
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.about_clipboard_label)
    val clipboardVersionLine = stringResource(R.string.about_clipboard_version_line, versionName, versionCode)
    val clipboardBuildTimeLine = stringResource(
        R.string.about_clipboard_build_time_line,
        formatBuildTimeUtc(buildTimeUtc),
    )
    val clipboardBuildHashLine = stringResource(R.string.about_clipboard_build_hash_line, buildHash)
    val copyToast = stringResource(R.string.about_copy_toast)

    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Surface(
                    shape = ShapeTokens.CornerLarge,
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                ) {
                    Box(
                        modifier = Modifier
                            .size(42.dp)
                            .padding(10.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Info,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }

                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    WrapSafeText(
                        text = stringResource(R.string.about_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = stringResource(R.string.about_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                AboutInfoRow(
                    label = stringResource(R.string.about_label_version),
                    value = stringResource(R.string.about_value_version, versionName, versionCode),
                    icon = Icons.Rounded.Badge,
                )
                AboutInfoRow(
                    label = stringResource(R.string.about_label_website),
                    value = ABOUT_WEBSITE,
                    icon = Icons.Rounded.Language,
                    onClick = { uriHandler.openUri("https://$ABOUT_WEBSITE") },
                )
                AboutInfoRow(
                    label = stringResource(R.string.social_github),
                    value = ABOUT_GITHUB_REPOSITORY,
                    iconPainter = painterResource(R.drawable.ic_github),
                    onClick = { uriHandler.openUri(ABOUT_GITHUB_URL) },
                )
                AboutInfoRow(
                    label = stringResource(R.string.about_label_email),
                    value = ABOUT_EMAIL,
                    icon = Icons.Rounded.Email,
                    onClick = { uriHandler.openUri("mailto:$ABOUT_EMAIL") },
                )
                AboutInfoRow(
                    label = stringResource(R.string.about_label_build_time),
                    value = stringResource(
                        R.string.about_value_build_time,
                        formatBuildTimeUtc(buildTimeUtc),
                    ),
                    icon = Icons.Rounded.Schedule,
                )
                AboutInfoRow(
                    label = stringResource(R.string.about_label_build_hash),
                    value = buildHash,
                    icon = Icons.Rounded.Badge,
                )
                AboutInfoRow(
                    label = stringResource(R.string.about_label_privacy),
                    value = stringResource(R.string.about_privacy_summary),
                    icon = Icons.Rounded.Info,
                )
                AboutInfoRow(
                    label = stringResource(R.string.about_label_copy_build_info),
                    value = stringResource(R.string.about_copy_build_info_summary),
                    icon = Icons.Rounded.ContentCopy,
                    onClick = {
                        val clipboard =
                            context.getSystemService(android.content.ClipboardManager::class.java)
                        clipboard?.setPrimaryClip(
                            ClipData.newPlainText(
                                clipboardLabel,
                                buildClipboardText(
                                    clipboardVersionLine = clipboardVersionLine,
                                    clipboardBuildTimeLine = clipboardBuildTimeLine,
                                    clipboardBuildHashLine = clipboardBuildHashLine,
                                ),
                            ),
                        )
                        Toast.makeText(
                            context,
                            copyToast,
                            Toast.LENGTH_SHORT,
                        ).show()
                    },
                )
            }
        }
    }
}

private fun buildClipboardText(
    clipboardVersionLine: String,
    clipboardBuildTimeLine: String,
    clipboardBuildHashLine: String,
): String {
    return listOf(
        clipboardVersionLine,
        clipboardBuildTimeLine,
        clipboardBuildHashLine,
    ).joinToString(separator = "\n")
}

@Composable
private fun AboutInfoRow(
    label: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    onClick: (() -> Unit)? = null,
) {
    AboutInfoRow(
        label = label,
        value = value,
        onClick = onClick,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun AboutInfoRow(
    label: String,
    value: String,
    iconPainter: Painter,
    onClick: (() -> Unit)? = null,
) {
    AboutInfoRow(
        label = label,
        value = value,
        onClick = onClick,
    ) {
        Icon(
            painter = iconPainter,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun AboutInfoRow(
    label: String,
    value: String,
    onClick: (() -> Unit)? = null,
    iconContent: @Composable () -> Unit,
) {
    Surface(
        shape = ShapeTokens.CornerLarge,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(enabled = onClick != null) {
                    onClick?.invoke()
                }
                .padding(horizontal = 14.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            iconContent()

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                WrapSafeText(
                    text = label,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                WrapSafeText(
                    text = value,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}
