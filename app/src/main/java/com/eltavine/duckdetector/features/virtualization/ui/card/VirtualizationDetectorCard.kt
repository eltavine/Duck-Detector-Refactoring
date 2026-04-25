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

package com.eltavine.duckdetector.features.virtualization.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.MenuBook
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.FolderZip
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.SyncAlt
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
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationCardModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationDetailRowModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationHeaderFactModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun VirtualizationDetectorCard(
    model: VirtualizationCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Dns,
        modifier = modifier,
        headerFacts = {
            VirtualizationCollapsedOverview(model)
        },
    ) {
        if (model.environmentRows.isNotEmpty()) {
            VirtualizationDetailSection("Environment", Icons.Rounded.Info, model.environmentRows)
        }
        if (model.runtimeRows.isNotEmpty()) {
            VirtualizationDetailSection("Runtime", Icons.Rounded.Memory, model.runtimeRows)
        }
        if (model.consistencyRows.isNotEmpty()) {
            VirtualizationDetailSection("Consistency", Icons.Rounded.SyncAlt, model.consistencyRows)
        }
        if (model.honeypotRows.isNotEmpty()) {
            VirtualizationDetailSection("Honeypots", Icons.Rounded.Search, model.honeypotRows)
        }
        if (model.hostAppRows.isNotEmpty()) {
            VirtualizationDetailSection("Host Apps", Icons.Rounded.FolderZip, model.hostAppRows)
        }
        if (model.impactItems.isNotEmpty()) {
            VirtualizationImpactSection("Impact", Icons.Rounded.CrisisAlert, model.impactItems)
        }
        if (model.methodRows.isNotEmpty()) {
            VirtualizationDetailSection("Detection Methods", Icons.Rounded.Search, model.methodRows)
        }
        if (model.scanRows.isNotEmpty()) {
            VirtualizationDetailSection("Scan State", Icons.Rounded.Info, model.scanRows)
        }
        if (model.references.isNotEmpty()) {
            DetectorSectionFrame(
                title = "References",
                icon = Icons.AutoMirrored.Rounded.MenuBook,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    model.references.forEach { reference ->
                        WrapSafeText(
                            text = reference,
                            modifier = Modifier.fillMaxWidth(),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun VirtualizationCollapsedOverview(
    model: VirtualizationCardModel,
) {
    val first = model.headerFacts.getOrNull(0) ?: return
    val second = model.headerFacts.getOrNull(1) ?: return
    val third = model.headerFacts.getOrNull(2) ?: return
    val fourth = model.headerFacts.getOrNull(3) ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        VirtualizationFactPairCard(
            primary = first,
            secondary = second,
            modifier = Modifier.weight(1f),
        )
        VirtualizationFactPairCard(
            primary = third,
            secondary = fourth,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun VirtualizationFactPairCard(
    primary: VirtualizationHeaderFactModel,
    secondary: VirtualizationHeaderFactModel,
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
            VirtualizationFactPairRow(primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            VirtualizationFactPairRow(secondary)
        }
    }
}

@Composable
private fun VirtualizationFactPairRow(
    fact: VirtualizationHeaderFactModel,
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
private fun VirtualizationDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<VirtualizationDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                VirtualizationDetailRow(row)
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
private fun VirtualizationDetailRow(
    row: VirtualizationDetailRowModel,
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
private fun VirtualizationImpactSection(
    title: String,
    icon: ImageVector,
    items: List<VirtualizationImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                VirtualizationImpactRow(item)
            }
        }
    }
}

@Composable
private fun VirtualizationImpactRow(
    item: VirtualizationImpactItemModel,
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
            modifier = Modifier.size(18.dp),
        )
        WrapSafeText(
            text = item.text,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
