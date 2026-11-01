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
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsTargetAppModel
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveDetailSectionTitle
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveMetricSummaryCard
import io.github.xiaotong6666.uihelper.adaptive.DetailMetric
import io.github.xiaotong6666.uihelper.adaptive.DetailTextRow
import io.github.xiaotong6666.uihelper.adaptive.adaptiveGroupedTextRows
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue
import io.github.xiaotong6666.uihelper.dialog.AdaptiveDetailsDialog

@Composable
internal fun DangerousAppsTargetsDialog(
    show: Boolean,
    targets: List<DangerousAppsTargetAppModel>,
    onDismiss: () -> Unit,
) {
    val categoryCount = targets.map { it.category }.distinct().size
    val groupedTargets = remember(targets) { targets.groupBy { it.category } }
    // Leave the Material dialog's header and close action outside the scrolling content.
    val maxListHeight = adaptiveValue(material = 500.dp, miuix = 440.dp)
    val targetLabel = stringResource(R.string.target_app_list_targets)
    val categoryLabel = stringResource(R.string.target_app_list_categories)
    val overviewLabel = stringResource(R.string.target_app_list_overview)

    AdaptiveDetailsDialog(
        show = show,
        title = stringResource(R.string.target_app_list_title),
        summary = stringResource(R.string.target_app_list_summary),
        icon = Icons.Rounded.Apps,
        closeLabel = stringResource(R.string.target_app_list_close),
        onDismiss = onDismiss,
        materialTitleStyle = MaterialTheme.typography.titleLarge,
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxWidth().heightIn(max = maxListHeight),
            verticalArrangement = Arrangement.spacedBy(0.dp),
        ) {
            item(key = "overview-title") {
                AdaptiveDetailSectionTitle(text = overviewLabel, topPadding = 0.dp)
            }
            item(key = "overview-card") {
                AdaptiveMetricSummaryCard(
                    metrics = listOf(
                        DetailMetric(value = targets.size.toString(), label = targetLabel),
                        DetailMetric(value = categoryCount.toString(), label = categoryLabel),
                    ),
                    modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
                )
            }
            groupedTargets.forEach { (category, categoryTargets) ->
                item(key = "title:$category") {
                    AdaptiveDetailSectionTitle(text = category)
                }
                adaptiveGroupedTextRows(
                    keyPrefix = "group:$category",
                    rows = categoryTargets.mapIndexed { index, target ->
                        DetailTextRow(
                            title = target.appName,
                            summary = target.packageName,
                            key = "${target.packageName}:$index",
                        )
                    },
                    miuixBottomPadding = 8.dp,
                    materialBottomPadding = 10.dp,
                )
            }
        }
    }
}

