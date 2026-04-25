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

package com.eltavine.duckdetector.features.nativeroot.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
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
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootCardModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootDetailRowModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootHeaderFactModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun NativeRootDetectorCard(
    model: NativeRootCardModel,
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
            NativeRootCollapsedOverview(model = model)
        },
    ) {
        if (model.nativeRows.isNotEmpty()) {
            NativeRootDetailSection(
                title = "Native probes",
                icon = Icons.Rounded.Security,
                rows = model.nativeRows,
            )
        }

        if (model.runtimeRows.isNotEmpty()) {
            NativeRootDetailSection(
                title = "Runtime artifacts",
                icon = Icons.Rounded.Shield,
                rows = model.runtimeRows,
            )
        }

        if (model.kernelRows.isNotEmpty()) {
            NativeRootDetailSection(
                title = "Kernel traces",
                icon = Icons.Rounded.Memory,
                rows = model.kernelRows,
            )
        }

        if (model.propertyRows.isNotEmpty()) {
            NativeRootDetailSection(
                title = "Property residue",
                icon = Icons.Rounded.Info,
                rows = model.propertyRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            NativeRootImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            NativeRootDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.scanRows.isNotEmpty()) {
            NativeRootDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun NativeRootCollapsedOverview(
    model: NativeRootCardModel,
) {
    val flags = model.headerFacts.firstOrNull { it.label == "Flags" } ?: return
    val direct = model.headerFacts.firstOrNull { it.label == "Direct" } ?: return
    val kernel = model.headerFacts.firstOrNull { it.label == "Kernel" } ?: return
    val runtime = model.headerFacts.firstOrNull { it.label == "Runtime" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        NativeRootFactPairCard(
            primary = flags,
            secondary = direct,
            modifier = Modifier.weight(1f),
        )
        NativeRootFactPairCard(
            primary = kernel,
            secondary = runtime,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun NativeRootFactPairCard(
    primary: NativeRootHeaderFactModel,
    secondary: NativeRootHeaderFactModel,
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
            NativeRootFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            NativeRootFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun NativeRootFactPairRow(
    fact: NativeRootHeaderFactModel,
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
private fun NativeRootDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<NativeRootDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                NativeRootDetailRow(row = row)
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
private fun NativeRootDetailRow(
    row: NativeRootDetailRowModel,
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
private fun NativeRootImpactSection(
    title: String,
    icon: ImageVector,
    items: List<NativeRootImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                NativeRootImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun NativeRootImpactRow(
    item: NativeRootImpactItemModel,
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
