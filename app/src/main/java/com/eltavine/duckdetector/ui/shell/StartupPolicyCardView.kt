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

package com.eltavine.duckdetector.ui.shell

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DisplaySettings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.designsystem.theme.ContinuousCornerShape
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveSingleChoiceButtonGroup
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Button as MiuixButton
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.theme.MiuixTheme

private val IconTileShape = ContinuousCornerShape(11.dp)

@Composable
internal fun StartupPolicyCard(
    card: StartupPolicyCardUi,
) {
    AdaptiveContent(
        miuix = { StartupPolicyCardMiuix(card) },
        material = { StartupPolicyCardMaterial(card) },
    )
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
internal fun StartupUiStyleCard(
    uiMode: UiMode,
    onUiModeChange: (UiMode) -> Unit,
) {
    AdaptiveContent(
        miuix = {
            MiuixCard(
                modifier = Modifier.fillMaxWidth(),
                insideMargin = PaddingValues(0.dp),
            ) {
                BasicComponent(
                    title = stringResource(R.string.startup_ui_style_title),
                    summary = stringResource(R.string.startup_ui_style_detail),
                    startAction = {
                        DuckIcon(
                            imageVector = Icons.Rounded.DisplaySettings,
                            contentDescription = null,
                            tint = MiuixTheme.colorScheme.onSurface,
                            modifier = Modifier.padding(end = 12.dp).size(22.dp),
                        )
                    },
                )
                AdaptiveSingleChoiceButtonGroup(
                    labels = listOf(
                        stringResource(R.string.startup_ui_style_material),
                        stringResource(R.string.startup_ui_style_miuix),
                    ),
                    selectedIndex = if (uiMode == UiMode.Material) 0 else 1,
                    onSelectedIndexChange = { index ->
                        onUiModeChange(if (index == 0) UiMode.Material else UiMode.Miuix)
                    },
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                )
            }
        },
        material = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        color = DuckTheme.palette.groupedSurface,
                        shape = MaterialTheme.shapes.large,
                    )
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Box(
                        modifier = Modifier
                            .size(40.dp)
                            .background(
                                color = DuckTheme.palette.groupedInset,
                                shape = MaterialTheme.shapes.medium,
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        DuckIcon(
                            imageVector = Icons.Rounded.DisplaySettings,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.size(22.dp),
                        )
                    }
                    WrapSafeText(
                        text = stringResource(R.string.startup_ui_style_title),
                        style = DuckTypography.Headline,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
                WrapSafeText(
                    text = stringResource(R.string.startup_ui_style_detail),
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                AdaptiveSingleChoiceButtonGroup(
                    labels = listOf(
                        stringResource(R.string.startup_ui_style_material),
                        stringResource(R.string.startup_ui_style_miuix),
                    ),
                    selectedIndex = if (uiMode == UiMode.Material) 0 else 1,
                    onSelectedIndexChange = { index ->
                        onUiModeChange(if (index == 0) UiMode.Material else UiMode.Miuix)
                    },
                )
            }
        },
    )
}

@Composable
private fun StartupPolicyCardMiuix(card: StartupPolicyCardUi) {
    MiuixCard(
        modifier = Modifier.fillMaxWidth(),
        insideMargin = PaddingValues(0.dp),
    ) {
        BasicComponent(
            title = card.title,
            summary = card.headline,
            startAction = {
                DuckIcon(
                    imageVector = card.icon,
                    contentDescription = null,
                    tint = MiuixTheme.colorScheme.onSurface,
                    modifier = Modifier.padding(end = 12.dp).size(22.dp),
                )
            },
            endActions = {
                MiuixText(
                    text = card.statusLabel,
                    style = MiuixTheme.textStyles.body2,
                    color = if (card.requiresAction) {
                        MiuixTheme.colorScheme.onSurface
                    } else {
                        MiuixTheme.colorScheme.onSurfaceVariantActions
                    },
                )
            },
        )
        MiuixText(
            text = card.detail,
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 12.dp),
            style = MiuixTheme.textStyles.body2,
            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
        )
        PolicyActionsMiuix(card)
    }
}

@Composable
private fun StartupPolicyCardMaterial(card: StartupPolicyCardUi) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = DuckTheme.palette.groupedSurface,
                shape = MaterialTheme.shapes.large,
            )
            .animateContentSize(MotionTokens.smoothSpring())
            .padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(color = DuckTheme.palette.groupedInset, shape = MaterialTheme.shapes.medium),
                contentAlignment = Alignment.Center,
            ) {
                DuckIcon(
                    imageVector = card.icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.size(22.dp),
                )
            }
            WrapSafeText(
                text = card.title,
                modifier = Modifier.weight(1f),
                style = DuckTypography.Headline,
                color = MaterialTheme.colorScheme.onSurface,
            )
            PolicyStatusCapsule(
                label = card.statusLabel,
                tone = card.tone,
            )
        }

        Column(
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            WrapSafeText(
                text = card.headline,
                style = DuckTypography.Body,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = card.detail,
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        PolicyActions(card = card)
    }
}
