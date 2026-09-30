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

package com.eltavine.duckdetector.features.lsposed.ui.card

import com.eltavine.duckdetector.features.lsposed.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Extension
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Search
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
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
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedCardModel
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedDetailRowModel
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedHeaderFact
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedHeaderFactModel
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedImpactItemModel
import com.eltavine.duckdetector.features.lsposed.presentation.model.LSPosedRowIcon
@Composable
internal fun LSPosedDetectorCard(
    model: LSPosedCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Extension,
        miuixLeadingPainter = painterResource(R.drawable.ic_lsposed_miuix),
        modifier = modifier,
        headerFacts = {
            LSPosedCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.runtimeRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_runtime_checks),
                icon = Icons.Rounded.BugReport,
                rows = model.runtimeRows,
                showDivider = model.binderRows.isNotEmpty() || model.packageRows.isNotEmpty() ||
                    model.policyRows.isNotEmpty() || model.nativeRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.binderRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_binder_services),
                icon = Icons.Rounded.AccountTree,
                rows = model.binderRows,
                showDivider = model.packageRows.isNotEmpty() || model.policyRows.isNotEmpty() ||
                    model.nativeRows.isNotEmpty() || model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() ||
                    model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.packageRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_packages_modules),
                icon = Icons.Rounded.Apps,
                rows = model.packageRows,
                showDivider = model.policyRows.isNotEmpty() || model.nativeRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.policyRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_selinux_policy),
                icon = Icons.Rounded.Security,
                rows = model.policyRows,
                showDivider = model.nativeRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.nativeRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_native_traces),
                icon = Icons.Rounded.Memory,
                rows = model.nativeRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.impactItems.isNotEmpty()) {
                LSPosedImpactSection(
                title = stringResource(R.string.lsposed_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.methodRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.scanRows.isNotEmpty()) {
                LSPosedDetailSection(
                title = stringResource(R.string.lsposed_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun LSPosedCollapsedOverview(
    model: LSPosedCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.fact == LSPosedHeaderFact.CRITICAL } ?: return
    val review = model.headerFacts.firstOrNull { it.fact == LSPosedHeaderFact.REVIEW } ?: return
    val bridge = model.headerFacts.firstOrNull { it.fact == LSPosedHeaderFact.BRIDGE } ?: return
    val packages = model.headerFacts.firstOrNull { it.fact == LSPosedHeaderFact.PACKAGES } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
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
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun LSPosedHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun LSPosedDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<LSPosedDetailRowModel>,
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
                LSPosedDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
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

private fun rowIcon(
    row: LSPosedDetailRowModel,
    fallback: ImageVector,
): ImageVector {
    return when (row.icon) {
        LSPosedRowIcon.BRIDGE -> Icons.Rounded.AccountTree
        LSPosedRowIcon.PACKAGE -> Icons.Rounded.Apps
        LSPosedRowIcon.MEMORY -> Icons.Rounded.Memory
        LSPosedRowIcon.POLICY -> Icons.Rounded.Security
        LSPosedRowIcon.HOOK -> Icons.Rounded.BugReport
        null -> fallback
    }
}
