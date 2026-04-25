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

package com.eltavine.duckdetector.features.systemproperties.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.CompareArrows
import androidx.compose.material.icons.automirrored.rounded.FactCheck
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.SettingsSuggest
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.ViewInAr
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesCardModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesDetailRowModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesHeaderFactModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun SystemPropertiesDetectorCard(
    model: SystemPropertiesCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.SettingsSuggest,
        modifier = modifier,
        headerFacts = {
            SystemPropertiesCollapsedOverview(model = model)
        },
    ) {
        if (model.coreRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Security and runtime",
                icon = Icons.Rounded.Shield,
                rows = model.coreRows,
            )
        }

        if (model.bootRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Verified boot",
                icon = Icons.Rounded.VerifiedUser,
                rows = model.bootRows,
            )
        }

        if (model.buildRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Build profile",
                icon = Icons.Rounded.ViewInAr,
                rows = model.buildRows,
            )
        }

        if (model.sourceRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Source consistency",
                icon = Icons.AutoMirrored.Rounded.CompareArrows,
                rows = model.sourceRows,
            )
        }

        if (model.consistencyRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Cross-check rules",
                icon = Icons.AutoMirrored.Rounded.FactCheck,
                rows = model.consistencyRows,
            )
        }

        if (model.infoRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Device info",
                icon = Icons.Rounded.Fingerprint,
                rows = model.infoRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            SystemPropertiesImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.scanRows.isNotEmpty()) {
            SystemPropertiesDetailSection(
                title = "Scan summary",
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
            )
        }
    }
}

@Composable
private fun SystemPropertiesCollapsedOverview(
    model: SystemPropertiesCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.label == "Critical" } ?: return
    val review = model.headerFacts.firstOrNull { it.label == "Review" } ?: return
    val boot = model.headerFacts.firstOrNull { it.label == "Boot" } ?: return
    val build = model.headerFacts.firstOrNull { it.label == "Build" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        SystemPropertiesFactPairCard(
            primary = critical,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        SystemPropertiesFactPairCard(
            primary = boot,
            secondary = build,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun SystemPropertiesFactPairCard(
    primary: SystemPropertiesHeaderFactModel,
    secondary: SystemPropertiesHeaderFactModel,
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
            SystemPropertiesFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            SystemPropertiesFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun SystemPropertiesFactPairRow(
    fact: SystemPropertiesHeaderFactModel,
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
private fun SystemPropertiesDetailSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    rows: List<SystemPropertiesDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                SystemPropertiesDetailRow(row = row)
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
private fun SystemPropertiesDetailRow(
    row: SystemPropertiesDetailRowModel,
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
private fun SystemPropertiesImpactSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    items: List<SystemPropertiesImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                SystemPropertiesImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun SystemPropertiesImpactRow(
    item: SystemPropertiesImpactItemModel,
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
