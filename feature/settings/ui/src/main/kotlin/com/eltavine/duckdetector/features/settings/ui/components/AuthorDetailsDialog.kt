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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledTonalButton
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.AdaptiveShapeTokens
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.settings.ui.R
import com.eltavine.duckdetector.core.ui.R as CoreUiR
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIconLabelChip
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.basic.Button as MiuixButton
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.overlay.OverlayDialog

@Composable
internal fun AuthorDetailsDialog(
    show: Boolean,
    profile: AuthorProfile,
    onDismiss: () -> Unit,
    onDismissFinished: () -> Unit = {},
) {
    val context = LocalContext.current
    if (LocalUiMode.current == UiMode.Miuix) {
        OverlayDialog(
            show = show,
            title = profile.name,
            summary = if (profile.name != profile.login) "@${profile.login}" else null,
            onDismissRequest = onDismiss,
            onDismissFinished = onDismissFinished,
        ) {
            Column(
                modifier = Modifier.fillMaxWidth().heightIn(max = 540.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().weight(1f, fill = false).verticalScroll(rememberScrollState()),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    AuthorAvatar(profile = profile, modifier = Modifier.size(96.dp))
                    MiuixText(
                        text = profile.contributionSummary,
                        modifier = Modifier.fillMaxWidth(),
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                    if (profile.contributions.isNotEmpty()) {
                        FlowRow(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            profile.contributions.forEach { contribution -> ContributionBadge(contribution) }
                        }
                    }
                }
                val viewGithub = stringResource(R.string.author_view_github)
                val fontScale = LocalConfiguration.current.fontScale
                BoxWithConstraints(modifier = Modifier.fillMaxWidth()) {
                    // Use genuinely equal-width actions when both labels can fit.
                    // On phones / enlarged text, stack two full-width actions rather
                    // than making the GitHub button wider or wrapping its label.
                    val stacked = maxWidth < 440.dp || fontScale > 1.1f
                    if (stacked) {
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            MiuixButton(
                                onClick = { openExternalUri(context, profile.profileUrl) },
                                modifier = Modifier.fillMaxWidth(),
                                colors = MiuixButtonDefaults.buttonColorsPrimary(),
                            ) {
                                MiuixText(text = viewGithub, maxLines = 1, softWrap = false)
                            }
                            MiuixTextButton(
                                text = stringResource(R.string.author_details_close),
                                onClick = onDismiss,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                            MiuixTextButton(
                                text = stringResource(R.string.author_details_close),
                                onClick = onDismiss,
                                modifier = Modifier.weight(1f),
                            )
                            MiuixButton(
                                onClick = { openExternalUri(context, profile.profileUrl) },
                                modifier = Modifier.weight(1f),
                                colors = MiuixButtonDefaults.buttonColorsPrimary(),
                                insideMargin = PaddingValues(horizontal = 8.dp, vertical = 13.dp),
                            ) {
                                MiuixText(text = viewGithub, maxLines = 1, softWrap = false)
                            }
                        }
                    }
                }
            }
        }
        return
    }
    if (!show) return
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = AdaptiveShapeTokens.CornerExtraLarge,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                AuthorAvatar(profile = profile, modifier = Modifier.size(104.dp))
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    WrapSafeText(
                        text = profile.name,
                        style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    if (profile.name != profile.login) {
                        WrapSafeText(
                            text = "@${profile.login}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
                WrapSafeText(
                    text = profile.contributionSummary,
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (profile.contributions.isNotEmpty()) {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        profile.contributions.forEach { contribution ->
                            ContributionBadge(contribution)
                        }
                    }
                }
            }
        },
        confirmButton = {
            FilledTonalButton(onClick = { openExternalUri(context, profile.profileUrl) }) {
                DuckIcon(
                    painter = painterResource(CoreUiR.drawable.ic_github),
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                WrapSafeText(
                    text = stringResource(R.string.author_view_github),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                WrapSafeText(text = stringResource(R.string.author_details_close))
            }
        },
    )
}

@Composable
private fun ContributionBadge(contribution: AuthorContribution) {
    AdaptiveIconLabelChip(
        icon = contribution.icon,
        label = contribution.label,
        materialShape = ShapeTokens.CornerFull,
        miuixCornerRadius = 12.dp,
        iconTint = contribution.tint,
        iconSize = 18.dp,
        materialTextStyle = MaterialTheme.typography.labelMedium,
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        useNativeCardSurface = true,
    )
}
