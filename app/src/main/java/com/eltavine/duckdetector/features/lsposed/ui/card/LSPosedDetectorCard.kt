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

package com.eltavine.duckdetector.features.lsposed.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
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
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedCardModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedDetailRowModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedHeaderFactModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun LSPosedDetectorCard(
    model: LSPosedCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.BugReport,
        modifier = modifier,
        headerFacts = {
            LSPosedCollapsedOverview(model = model)
        },
    ) {
        if (model.runtimeRows.isNotEmpty()) {
            LSPosedDetailSection(
                title = "Runtime checks",
                icon = Icons.Rounded.BugReport,
                rows = model.runtimeRows,
            )
        }
        if (model.binderRows.isNotEmpty()) {
            LSPosedDetailSection(
                title = "Binder and services",
                icon = Icons.Rounded.AccountTree,
                rows = model.binderRows,
            )
        }
        if (model.packageRows.isNotEmpty()) {
            LSPosedDetailSection(
                title = "Packages and modules",
                icon = Icons.Rounded.Apps,
                rows = model.packageRows,
            )
        }
        if (model.nativeRows.isNotEmpty()) {
            LSPosedDetailSection(
                title = "Native traces",
                icon = Icons.Rounded.Memory,
                rows = model.nativeRows,
            )
        }
        if (model.impactItems.isNotEmpty()) {
            LSPosedImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }
        if (model.methodRows.isNotEmpty()) {
            LSPosedDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }
        if (model.scanRows.isNotEmpty()) {
            LSPosedDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun LSPosedCollapsedOverview(
    model: LSPosedCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.label == "Critical" } ?: return
    val review = model.headerFacts.firstOrNull { it.label == "Review" } ?: return
    val bridge = model.headerFacts.firstOrNull { it.label == "Bridge" } ?: return
    val packages = model.headerFacts.firstOrNull { it.label == "Packages" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        LSPosedFactPairCard(
            primary = critical,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        LSPosedFactPairCard(
            primary = bridge,
            secondary = packages,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun LSPosedFactPairCard(
    primary: LSPosedHeaderFactModel,
    secondary: LSPosedHeaderFactModel,
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
            LSPosedFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            LSPosedFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun LSPosedFactPairRow(
    fact: LSPosedHeaderFactModel,
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
private fun LSPosedDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<LSPosedDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                LSPosedDetailRow(row = row)
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
private fun LSPosedDetailRow(
    row: LSPosedDetailRowModel,
) {
    val appearance = rememberStatusAppearance(row.status)
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        detail = row.detail,
        detailMonospace = row.detailMonospace,
        statusIcon = rowIcon(row, appearance.icon),
    )
}

@Composable
private fun LSPosedImpactSection(
    title: String,
    icon: ImageVector,
    items: List<LSPosedImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                LSPosedImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun LSPosedImpactRow(
    item: LSPosedImpactItemModel,
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

private fun rowIcon(
    row: LSPosedDetailRowModel,
    fallback: ImageVector,
): ImageVector {
    return when {
        row.label.contains("bridge", ignoreCase = true) ||
                row.label.contains("service", ignoreCase = true) -> Icons.Rounded.AccountTree

        row.value.equals("Installed", ignoreCase = true) ||
                row.value.equals("Module", ignoreCase = true) ||
                row.label.contains("package", ignoreCase = true) ||
                row.label.contains("manager", ignoreCase = true) -> Icons.Rounded.Apps

        row.value.equals("Mapped", ignoreCase = true) ||
                row.value.equals("Residual", ignoreCase = true) ||
                row.label.contains("heap", ignoreCase = true) ||
                row.label.contains("mapping", ignoreCase = true) -> Icons.Rounded.Memory

        row.label.contains("stack", ignoreCase = true) ||
                row.label.contains("xposed", ignoreCase = true) ||
                row.label.contains("lsposed", ignoreCase = true) -> Icons.Rounded.BugReport

        else -> fallback
    }
}
