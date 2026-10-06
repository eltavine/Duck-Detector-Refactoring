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

package com.eltavine.duckdetector.features.playintegrityfix.ui.card

import com.eltavine.duckdetector.features.playintegrityfix.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.CompareArrows
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VerifiedUser
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
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixCardModel
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixDetailRowModel
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixHeaderFact
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixHeaderFactModel
import com.eltavine.duckdetector.features.playintegrityfix.presentation.model.PlayIntegrityFixImpactItemModel

@Composable
internal fun PlayIntegrityFixDetectorCard(
    model: PlayIntegrityFixCardModel,
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
            PlayIntegrityFixCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.propertyRows.isNotEmpty()) {
                PlayIntegrityFixDetailSection(
                title = stringResource(R.string.playintegrityfix_section_spoof_properties),
                icon = Icons.Rounded.Shield,
                rows = model.propertyRows,
                showDivider = model.consistencyRows.isNotEmpty() || model.nativeRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.consistencyRows.isNotEmpty()) {
                PlayIntegrityFixDetailSection(
                title = stringResource(R.string.playintegrityfix_section_cross_source_consistency),
                icon = Icons.AutoMirrored.Rounded.CompareArrows,
                rows = model.consistencyRows,
                showDivider = model.nativeRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.nativeRows.isNotEmpty()) {
                PlayIntegrityFixDetailSection(
                title = stringResource(R.string.playintegrityfix_section_runtime_traces),
                icon = Icons.Rounded.Memory,
                rows = model.nativeRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                PlayIntegrityFixImpactSection(
                title = stringResource(R.string.playintegrityfix_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                PlayIntegrityFixDetailSection(
                title = stringResource(R.string.playintegrityfix_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                PlayIntegrityFixDetailSection(
                title = stringResource(R.string.playintegrityfix_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun PlayIntegrityFixCollapsedOverview(
    model: PlayIntegrityFixCardModel,
) {
    val direct = model.headerFacts.firstOrNull { it.fact == PlayIntegrityFixHeaderFact.DIRECT } ?: return
    val review = model.headerFacts.firstOrNull { it.fact == PlayIntegrityFixHeaderFact.REVIEW } ?: return
    val props = model.headerFacts.firstOrNull { it.fact == PlayIntegrityFixHeaderFact.PROPS } ?: return
    val native = model.headerFacts.firstOrNull { it.fact == PlayIntegrityFixHeaderFact.NATIVE } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        PlayIntegrityFixFactPairCard(
            primary = direct,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        PlayIntegrityFixFactPairCard(
            primary = props,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun PlayIntegrityFixFactPairCard(
    primary: PlayIntegrityFixHeaderFactModel,
    secondary: PlayIntegrityFixHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun PlayIntegrityFixHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun PlayIntegrityFixDetailSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    rows: List<PlayIntegrityFixDetailRowModel>,
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
                PlayIntegrityFixDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun PlayIntegrityFixDetailRow(
    row: PlayIntegrityFixDetailRowModel,
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
private fun PlayIntegrityFixImpactSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    items: List<PlayIntegrityFixImpactItemModel>,
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
                PlayIntegrityFixImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun PlayIntegrityFixImpactRow(
    item: PlayIntegrityFixImpactItemModel,
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
