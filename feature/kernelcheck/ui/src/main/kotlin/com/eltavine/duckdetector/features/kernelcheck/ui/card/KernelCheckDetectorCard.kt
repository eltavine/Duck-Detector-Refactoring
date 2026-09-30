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

package com.eltavine.duckdetector.features.kernelcheck.ui.card

import com.eltavine.duckdetector.features.kernelcheck.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DeveloperBoard
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Warning
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
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckCardModel
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckDetailRowModel
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckHeaderFact
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckHeaderFactModel
import com.eltavine.duckdetector.features.kernelcheck.presentation.model.KernelCheckImpactItemModel

@Composable
internal fun KernelCheckDetectorCard(
    model: KernelCheckCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.DeveloperBoard,
        modifier = modifier,
        headerFacts = {
            KernelCheckCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.identityRows.isNotEmpty()) {
                KernelCheckDetailSection(
                title = stringResource(R.string.kernelcheck_section_identity),
                icon = Icons.Rounded.Description,
                rows = model.identityRows,
                showDivider = model.anomalyRows.isNotEmpty() || model.behaviorRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.anomalyRows.isNotEmpty()) {
                KernelCheckDetailSection(
                title = stringResource(R.string.kernelcheck_section_anomalies),
                icon = Icons.Rounded.Warning,
                rows = model.anomalyRows,
                showDivider = model.behaviorRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.behaviorRows.isNotEmpty()) {
                KernelCheckDetailSection(
                title = stringResource(R.string.kernelcheck_section_behavior),
                icon = Icons.Rounded.BugReport,
                rows = model.behaviorRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                KernelCheckImpactSection(
                title = stringResource(R.string.kernelcheck_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                KernelCheckDetailSection(
                title = stringResource(R.string.kernelcheck_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                KernelCheckDetailSection(
                title = stringResource(R.string.kernelcheck_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun KernelCheckCollapsedOverview(
    model: KernelCheckCardModel,
) {
    val identity = model.headerFacts.firstOrNull { it.fact == KernelCheckHeaderFact.IDENTITY } ?: return
    val boot = model.headerFacts.firstOrNull { it.fact == KernelCheckHeaderFact.BOOT } ?: return
    val behavior = model.headerFacts.firstOrNull { it.fact == KernelCheckHeaderFact.BEHAVIOR } ?: return
    val native = model.headerFacts.firstOrNull { it.fact == KernelCheckHeaderFact.NATIVE } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        KernelCheckFactPairCard(
            primary = identity,
            secondary = boot,
            modifier = Modifier.weight(1f),
        )
        KernelCheckFactPairCard(
            primary = behavior,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun KernelCheckFactPairCard(
    primary: KernelCheckHeaderFactModel,
    secondary: KernelCheckHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun KernelCheckHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun KernelCheckDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<KernelCheckDetailRowModel>,
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
                KernelCheckDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun KernelCheckDetailRow(
    row: KernelCheckDetailRowModel,
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
private fun KernelCheckImpactSection(
    title: String,
    icon: ImageVector,
    items: List<KernelCheckImpactItemModel>,
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
                KernelCheckImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun KernelCheckImpactRow(
    item: KernelCheckImpactItemModel,
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
