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

package com.eltavine.duckdetector.features.customrom.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Build
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomCardModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomDetailRowModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomHeaderFactModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun CustomRomDetectorCard(
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
        if (model.buildRows.isNotEmpty()) {
            CustomRomDetailSection(
                title = "Build signals",
                icon = Icons.Rounded.Build,
                rows = model.buildRows,
            )
        }

        if (model.runtimeRows.isNotEmpty()) {
            CustomRomDetailSection(
                title = "Runtime signals",
                icon = Icons.Rounded.Apps,
                rows = model.runtimeRows,
            )
        }

        if (model.frameworkRows.isNotEmpty()) {
            CustomRomDetailSection(
                title = "Framework traces",
                icon = Icons.Rounded.Folder,
                rows = model.frameworkRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            CustomRomImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            CustomRomDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.scanRows.isNotEmpty()) {
            CustomRomDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun CustomRomCollapsedOverview(
    model: CustomRomCardModel,
) {
    val roms = model.headerFacts.firstOrNull { it.label == "ROMs" } ?: return
    val build = model.headerFacts.firstOrNull { it.label == "Build" } ?: return
    val runtime = model.headerFacts.firstOrNull { it.label == "Runtime" } ?: return
    val native = model.headerFacts.firstOrNull { it.label == "Native" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
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
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            CustomRomFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            CustomRomFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun CustomRomFactPairRow(
    fact: CustomRomHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = fact.label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun CustomRomDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<CustomRomDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                CustomRomDetailRow(row = row)
                if (index < rows.lastIndex) {
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                        thickness = 1.dp,
                    )
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
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
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
        Icon(
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
