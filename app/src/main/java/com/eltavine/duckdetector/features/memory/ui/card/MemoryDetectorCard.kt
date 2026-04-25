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

package com.eltavine.duckdetector.features.memory.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Map
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Visibility
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
import com.eltavine.duckdetector.features.memory.ui.model.MemoryCardModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryDetailRowModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryHeaderFactModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun MemoryDetectorCard(
    model: MemoryCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Memory,
        modifier = modifier,
        headerFacts = {
            MemoryCollapsedOverview(model = model)
        },
    ) {
        if (model.hookRows.isNotEmpty()) {
            MemoryDetailSection(
                title = "Function hooks",
                icon = Icons.Rounded.Memory,
                rows = model.hookRows,
            )
        }
        if (model.mappingRows.isNotEmpty()) {
            MemoryDetailSection(
                title = "Mappings and FD-backed code",
                icon = Icons.Rounded.Map,
                rows = model.mappingRows,
            )
        }
        if (model.loaderRows.isNotEmpty()) {
            MemoryDetailSection(
                title = "Loader visibility",
                icon = Icons.Rounded.Visibility,
                rows = model.loaderRows,
            )
        }
        if (model.impactItems.isNotEmpty()) {
            MemoryImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }
        if (model.methodRows.isNotEmpty()) {
            MemoryDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }
        if (model.scanRows.isNotEmpty()) {
            MemoryDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun MemoryCollapsedOverview(
    model: MemoryCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.label == "Critical" } ?: return
    val review = model.headerFacts.firstOrNull { it.label == "Review" } ?: return
    val hooks = model.headerFacts.firstOrNull { it.label == "Hooks" } ?: return
    val runtime = model.headerFacts.firstOrNull { it.label == "Runtime" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        MemoryFactPairCard(
            primary = critical,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        MemoryFactPairCard(
            primary = hooks,
            secondary = runtime,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun MemoryFactPairCard(
    primary: MemoryHeaderFactModel,
    secondary: MemoryHeaderFactModel,
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
            MemoryFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            MemoryFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun MemoryFactPairRow(
    fact: MemoryHeaderFactModel,
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
private fun MemoryDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<MemoryDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                MemoryDetailRow(row = row)
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
private fun MemoryDetailRow(
    row: MemoryDetailRowModel,
) {
    val appearance = rememberStatusAppearance(row.status)
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        detail = row.detail,
        detailMonospace = row.detailMonospace,
        statusIcon = when {
            row.label.contains("vDSO", ignoreCase = true) -> Icons.Rounded.Memory
            row.label.contains("signal", ignoreCase = true) -> Icons.Rounded.Visibility
            else -> appearance.icon
        },
    )
}

@Composable
private fun MemoryImpactSection(
    title: String,
    icon: ImageVector,
    items: List<MemoryImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                MemoryImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun MemoryImpactRow(
    item: MemoryImpactItemModel,
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
