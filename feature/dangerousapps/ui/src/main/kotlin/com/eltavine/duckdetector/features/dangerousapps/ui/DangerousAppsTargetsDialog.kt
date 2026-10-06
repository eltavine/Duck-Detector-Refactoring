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

package com.eltavine.duckdetector.features.dangerousapps.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Category
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsTargetAppModel
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveHorizontalDivider
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIconLabelChip
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveMetricChip
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveSurfaceTone
import io.github.xiaotong6666.uihelper.adaptive.adaptiveFootnoteStyle
import io.github.xiaotong6666.uihelper.adaptive.adaptiveHeadlineStyle
import io.github.xiaotong6666.uihelper.adaptive.adaptiveOnSurfaceColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSecondaryTextColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceBackground
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceClip
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceColor
import io.github.xiaotong6666.uihelper.dialog.AdaptiveDetailsDialog
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixMetricItem
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixMetricSummaryCard
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixSectionTitle
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixTextRow
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixTextRowsCard

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun DangerousAppsTargetsDialog(
    show: Boolean,
    targets: List<DangerousAppsTargetAppModel>,
    onDismiss: () -> Unit,
) {
    val categoryCount = targets.map { it.category }.distinct().size
    val listSurface = adaptiveSurfaceColor(AdaptiveSurfaceTone.Low)

    AdaptiveDetailsDialog(
        show = show,
        title = stringResource(R.string.target_app_list_title),
        summary = stringResource(R.string.target_app_list_summary),
        icon = Icons.Rounded.Apps,
        closeLabel = stringResource(R.string.target_app_list_close),
        onDismiss = onDismiss,
        materialTitleStyle = MaterialTheme.typography.titleLarge,
    ) {
        AdaptiveContent(
            material = {
                DangerousAppsTargetsMaterialContent(
                    targets = targets,
                    categoryCount = categoryCount,
                    listSurface = listSurface,
                )
            },
            miuix = {
                DangerousAppsTargetsMiuixContent(
                    targets = targets,
                    categoryCount = categoryCount,
                )
            },
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DangerousAppsTargetsMaterialContent(
    targets: List<DangerousAppsTargetAppModel>,
    categoryCount: Int,
    listSurface: androidx.compose.ui.graphics.Color,
) {
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AdaptiveMetricChip(
            icon = Icons.Rounded.Apps,
            label = stringResource(R.string.target_app_list_targets),
            value = targets.size.toString(),
            materialShape = ShapeTokens.CornerLarge,
        )
        AdaptiveMetricChip(
            icon = Icons.Rounded.Category,
            label = stringResource(R.string.target_app_list_categories),
            value = categoryCount.toString(),
            materialShape = ShapeTokens.CornerLarge,
        )
    }
    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 600.dp)
            .adaptiveSurfaceBackground(listSurface, ShapeTokens.CornerExtraLarge, listSurface, 16.dp)
            .adaptiveSurfaceClip(ShapeTokens.CornerExtraLarge, 16.dp),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
    ) {
        itemsIndexed(targets) { index, target ->
            DangerousAppsTargetRow(target)
            if (index < targets.lastIndex) {
                AdaptiveHorizontalDivider(
                    materialThickness = 1.dp,
                    materialColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                )
            }
        }
    }
}

@Composable
private fun DangerousAppsTargetsMiuixContent(
    targets: List<DangerousAppsTargetAppModel>,
    categoryCount: Int,
) {
    val groupedTargets = remember(targets) {
        targets
            .groupBy { it.category }
            .entries
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 440.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp),
    ) {
        item(key = "overview-title") {
            MiuixSectionTitle(
                text = stringResource(R.string.target_app_list_overview),
                topPadding = 0.dp,
            )
        }
        item(key = "overview-card") {
            MiuixMetricSummaryCard(
                metrics = listOf(
                    MiuixMetricItem(
                        value = targets.size.toString(),
                        label = stringResource(R.string.target_app_list_targets),
                    ),
                    MiuixMetricItem(
                        value = categoryCount.toString(),
                        label = stringResource(R.string.target_app_list_categories),
                    ),
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp),
            )
        }

        groupedTargets.forEach { (category, categoryTargets) ->
            item(key = "title:$category") {
                MiuixSectionTitle(text = category)
            }
            item(key = "group:$category") {
                MiuixTextRowsCard(
                    rows = categoryTargets.map { target ->
                        MiuixTextRow(
                            title = target.appName,
                            summary = target.packageName,
                        )
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun DangerousAppsTargetRow(
    target: DangerousAppsTargetAppModel,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            WrapSafeText(
                text = target.appName,
                modifier = Modifier.weight(1f),
                style = adaptiveHeadlineStyle(MaterialTheme.typography.titleSmall),
                color = adaptiveOnSurfaceColor(),
            )
            AdaptiveIconLabelChip(
                icon = Icons.Rounded.Shield,
                label = target.category,
                materialShape = ShapeTokens.CornerFull,
                miuixCornerRadius = 6.dp,
            )
        }
        WrapSafeText(
            text = target.packageName,
            style = adaptiveFootnoteStyle(MaterialTheme.typography.bodySmall).copy(fontFamily = FontFamily.Monospace),
            color = adaptiveSecondaryTextColor(),
        )
    }
}

