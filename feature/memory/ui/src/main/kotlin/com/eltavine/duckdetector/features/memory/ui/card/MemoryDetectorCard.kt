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

package com.eltavine.duckdetector.features.memory.ui.card

import com.eltavine.duckdetector.features.memory.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Map
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Visibility
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
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryCardModel
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryDetailRowModel
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryHeaderFact
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryHeaderFactModel
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryImpactItemModel
import com.eltavine.duckdetector.features.memory.presentation.model.MemoryRowIcon

@Composable
internal fun MemoryDetectorCard(
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
        DetectorSectionGroup {
            item(visible = model.hookRows.isNotEmpty()) {
                MemoryDetailSection(
                title = stringResource(R.string.memory_section_function_hooks),
                icon = Icons.Rounded.Memory,
                rows = model.hookRows,
                showDivider = model.mappingRows.isNotEmpty() || model.loaderRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.mappingRows.isNotEmpty()) {
                MemoryDetailSection(
                title = stringResource(R.string.memory_section_mappings_fd_code),
                icon = Icons.Rounded.Map,
                rows = model.mappingRows,
                showDivider = model.loaderRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.loaderRows.isNotEmpty()) {
                MemoryDetailSection(
                title = stringResource(R.string.memory_section_loader_visibility),
                icon = Icons.Rounded.Visibility,
                rows = model.loaderRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.impactItems.isNotEmpty()) {
                MemoryImpactSection(
                title = stringResource(R.string.memory_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.methodRows.isNotEmpty()) {
                MemoryDetailSection(
                title = stringResource(R.string.memory_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.scanRows.isNotEmpty()) {
                MemoryDetailSection(
                title = stringResource(R.string.memory_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun MemoryCollapsedOverview(
    model: MemoryCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.fact == MemoryHeaderFact.CRITICAL } ?: return
    val review = model.headerFacts.firstOrNull { it.fact == MemoryHeaderFact.REVIEW } ?: return
    val hooks = model.headerFacts.firstOrNull { it.fact == MemoryHeaderFact.HOOKS } ?: return
    val runtime = model.headerFacts.firstOrNull { it.fact == MemoryHeaderFact.RUNTIME } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
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
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun MemoryHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun MemoryDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<MemoryDetailRowModel>,
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
                MemoryDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
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
        statusIcon = when (row.icon) {
            MemoryRowIcon.VDSO -> Icons.Rounded.Memory
            MemoryRowIcon.SIGNAL_HANDLER -> Icons.Rounded.Visibility
            null -> appearance.icon
        },
    )
}

@Composable
private fun MemoryImpactSection(
    title: String,
    icon: ImageVector,
    items: List<MemoryImpactItemModel>,
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
