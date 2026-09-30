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

package com.eltavine.duckdetector.features.systemproperties.ui.card

import com.eltavine.duckdetector.features.systemproperties.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesCardModel
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesDetailRowModel
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesHeaderFact
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesHeaderFactModel
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesImpactItemModel

@Composable
internal fun SystemPropertiesDetectorCard(
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
        DetectorSectionGroup {
            item(visible = model.coreRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_security_runtime),
                icon = Icons.Rounded.Shield,
                rows = model.coreRows,
                showDivider = model.bootRows.isNotEmpty() || model.buildRows.isNotEmpty() ||
                    model.sourceRows.isNotEmpty() || model.consistencyRows.isNotEmpty() || model.infoRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.bootRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_verified_boot),
                icon = Icons.Rounded.VerifiedUser,
                rows = model.bootRows,
                showDivider = model.buildRows.isNotEmpty() || model.sourceRows.isNotEmpty() ||
                    model.consistencyRows.isNotEmpty() || model.infoRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.buildRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_build_profile),
                icon = Icons.Rounded.ViewInAr,
                rows = model.buildRows,
                showDivider = model.sourceRows.isNotEmpty() || model.consistencyRows.isNotEmpty() ||
                    model.infoRows.isNotEmpty() || model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() ||
                    model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.sourceRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_source_consistency),
                icon = Icons.AutoMirrored.Rounded.CompareArrows,
                rows = model.sourceRows,
                showDivider = model.consistencyRows.isNotEmpty() || model.infoRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.consistencyRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_cross_check_rules),
                icon = Icons.AutoMirrored.Rounded.FactCheck,
                rows = model.consistencyRows,
                showDivider = model.infoRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.infoRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_device_info),
                icon = Icons.Rounded.Fingerprint,
                rows = model.infoRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                SystemPropertiesImpactSection(
                title = stringResource(R.string.systemproperties_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                SystemPropertiesDetailSection(
                title = stringResource(R.string.systemproperties_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun SystemPropertiesCollapsedOverview(
    model: SystemPropertiesCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.fact == SystemPropertiesHeaderFact.CRITICAL } ?: return
    val review = model.headerFacts.firstOrNull { it.fact == SystemPropertiesHeaderFact.REVIEW } ?: return
    val boot = model.headerFacts.firstOrNull { it.fact == SystemPropertiesHeaderFact.BOOT } ?: return
    val build = model.headerFacts.firstOrNull { it.fact == SystemPropertiesHeaderFact.BUILD } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
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
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun SystemPropertiesHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun SystemPropertiesDetailSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    rows: List<SystemPropertiesDetailRowModel>,
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
                SystemPropertiesDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
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
