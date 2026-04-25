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

package com.eltavine.duckdetector.features.bootloader.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.FactCheck
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.VerifiedUser
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
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderCardModel
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderDetailRowModel
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderHeaderFactModel
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun BootloaderDetectorCard(
    model: BootloaderCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.VerifiedUser,
        modifier = modifier,
        headerFacts = {
            BootloaderCollapsedOverview(model = model)
        },
    ) {
        if (model.stateRows.isNotEmpty()) {
            BootloaderDetailSection(
                title = "Boot state",
                icon = Icons.Rounded.VerifiedUser,
                rows = model.stateRows,
            )
        }

        if (model.attestationRows.isNotEmpty()) {
            BootloaderDetailSection(
                title = "Attestation",
                icon = Icons.Rounded.Key,
                rows = model.attestationRows,
            )
        }

        if (model.propertyRows.isNotEmpty()) {
            BootloaderDetailSection(
                title = "Boot properties",
                icon = Icons.Rounded.Settings,
                rows = model.propertyRows,
            )
        }

        if (model.consistencyRows.isNotEmpty()) {
            BootloaderDetailSection(
                title = "Consistency",
                icon = Icons.AutoMirrored.Rounded.FactCheck,
                rows = model.consistencyRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            BootloaderImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            BootloaderDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.scanRows.isNotEmpty()) {
            BootloaderDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun BootloaderCollapsedOverview(
    model: BootloaderCardModel,
) {
    val state = model.headerFacts.firstOrNull { it.label == "State" } ?: return
    val proof = model.headerFacts.firstOrNull { it.label == "Proof" } ?: return
    val tier = model.headerFacts.firstOrNull { it.label == "Tier" } ?: return
    val trust = model.headerFacts.firstOrNull { it.label == "Trust" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        BootloaderFactPairCard(
            primary = state,
            secondary = proof,
            modifier = Modifier.weight(1f),
        )
        BootloaderFactPairCard(
            primary = tier,
            secondary = trust,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun BootloaderFactPairCard(
    primary: BootloaderHeaderFactModel,
    secondary: BootloaderHeaderFactModel,
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
            BootloaderFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            BootloaderFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun BootloaderFactPairRow(
    fact: BootloaderHeaderFactModel,
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
private fun BootloaderDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<BootloaderDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                BootloaderDetailRow(row = row)
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
private fun BootloaderDetailRow(
    row: BootloaderDetailRowModel,
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
private fun BootloaderImpactSection(
    title: String,
    icon: ImageVector,
    items: List<BootloaderImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                BootloaderImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun BootloaderImpactRow(
    item: BootloaderImpactItemModel,
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
