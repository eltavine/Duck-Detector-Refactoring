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

package com.eltavine.duckdetector.features.customrom.ui.card

import com.eltavine.duckdetector.features.customrom.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Search
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorFact
import com.eltavine.duckdetector.core.ui.components.DetectorFactPair
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionGroup
import com.eltavine.duckdetector.core.ui.components.highestSectionSeverity
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomCardModel
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomDetailRowModel
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomHeaderFact
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomHeaderFactModel
import com.eltavine.duckdetector.features.customrom.presentation.model.CustomRomImpactItemModel

@Composable
internal fun CustomRomDetectorCard(
    model: CustomRomCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Build,
        modifier = modifier,
        headerFacts = {
            CustomRomCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.buildRows.isNotEmpty()) {
                CustomRomDetailSection(
                title = stringResource(R.string.customrom_section_build_signals),
                icon = Icons.Rounded.Build,
                rows = model.buildRows,
                showDivider = model.runtimeRows.isNotEmpty() || model.frameworkRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.runtimeRows.isNotEmpty()) {
                CustomRomDetailSection(
                title = stringResource(R.string.customrom_section_runtime_signals),
                icon = Icons.Rounded.Apps,
                rows = model.runtimeRows,
                showDivider = model.frameworkRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.frameworkRows.isNotEmpty()) {
                CustomRomDetailSection(
                title = stringResource(R.string.customrom_section_framework_traces),
                icon = Icons.Rounded.Folder,
                rows = model.frameworkRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                CustomRomImpactSection(
                title = stringResource(R.string.customrom_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                CustomRomDetailSection(
                title = stringResource(R.string.customrom_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                CustomRomDetailSection(
                title = stringResource(R.string.customrom_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun CustomRomCollapsedOverview(
    model: CustomRomCardModel,
) {
    val roms = model.headerFacts.firstOrNull { it.fact == CustomRomHeaderFact.ROMS } ?: return
    val build = model.headerFacts.firstOrNull { it.fact == CustomRomHeaderFact.BUILD } ?: return
    val runtime = model.headerFacts.firstOrNull { it.fact == CustomRomHeaderFact.RUNTIME } ?: return
    val native = model.headerFacts.firstOrNull { it.fact == CustomRomHeaderFact.NATIVE } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        CustomRomFactPairCard(
            primary = roms,
            secondary = build,
            modifier = Modifier.weight(1f),
        )
        CustomRomFactPairCard(
            primary = runtime,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun CustomRomFactPairCard(
    primary: CustomRomHeaderFactModel,
    secondary: CustomRomHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun CustomRomHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun CustomRomDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<CustomRomDetailRowModel>,
    showDivider: Boolean = true,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
        severity = highestSectionSeverity(rows.map { it.status }),
        showDivider = showDivider,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                CustomRomDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun CustomRomDetailRow(
    row: CustomRomDetailRowModel,
) {
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        detail = row.detail,
        detailMonospace = row.detailMonospace,
    )
}

@Composable
private fun CustomRomImpactSection(
    title: String,
    icon: ImageVector,
    items: List<CustomRomImpactItemModel>,
    showDivider: Boolean = true,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
        severity = highestSectionSeverity(items.map { it.status }),
        showDivider = showDivider,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                CustomRomImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun CustomRomImpactRow(
    item: CustomRomImpactItemModel,
) {
    val appearance = rememberStatusAppearance(item.status)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        DuckIcon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = appearance.iconTint,
            modifier = Modifier.size(16.dp),
        )
        WrapSafeText(
            text = item.text,
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
