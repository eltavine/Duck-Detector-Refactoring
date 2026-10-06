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

package com.eltavine.duckdetector.features.virtualization.ui.card

import com.eltavine.duckdetector.features.virtualization.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationCardModel
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationDetailRowModel
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationHeaderFactModel
import com.eltavine.duckdetector.features.virtualization.presentation.model.VirtualizationImpactItemModel

@Composable
internal fun VirtualizationDetectorCard(
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
        DetectorSectionGroup {
            item(visible = model.environmentRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_environment),
                    Icons.Rounded.Info,
                    model.environmentRows,
                    showDivider = model.runtimeRows.isNotEmpty() || model.consistencyRows.isNotEmpty() ||
                        model.honeypotRows.isNotEmpty() || model.hostAppRows.isNotEmpty() ||
                        model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() ||
                        model.scanRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.runtimeRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_runtime),
                    Icons.Rounded.Memory,
                    model.runtimeRows,
                    showDivider = model.consistencyRows.isNotEmpty() || model.honeypotRows.isNotEmpty() ||
                        model.hostAppRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                        model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.consistencyRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_consistency),
                    Icons.Rounded.SyncAlt,
                    model.consistencyRows,
                    showDivider = model.honeypotRows.isNotEmpty() || model.hostAppRows.isNotEmpty() ||
                        model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() ||
                        model.scanRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.honeypotRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_honeypots),
                    Icons.Rounded.Search,
                    model.honeypotRows,
                    showDivider = model.hostAppRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                        model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.hostAppRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_host_apps),
                    Icons.Rounded.FolderZip,
                    model.hostAppRows,
                    showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() ||
                        model.scanRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.impactItems.isNotEmpty()) {
                VirtualizationImpactSection(
                    stringResource(R.string.virtualization_section_impact),
                    Icons.Rounded.CrisisAlert,
                    model.impactItems,
                    showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty() ||
                        model.references.isNotEmpty(),
                )
            }
            item(visible = model.methodRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_detection_methods),
                    Icons.Rounded.Search,
                    model.methodRows,
                    showDivider = model.scanRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.scanRows.isNotEmpty()) {
                VirtualizationDetailSection(
                    stringResource(R.string.virtualization_section_scan_state),
                    Icons.Rounded.Info,
                    model.scanRows,
                    showDivider = model.references.isNotEmpty(),
                )
            }
            item(visible = model.references.isNotEmpty()) {
                DetectorSectionFrame(
                    title = stringResource(R.string.virtualization_section_references),
                    icon = Icons.AutoMirrored.Rounded.MenuBook,
                    showDivider = false,
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
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
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
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun VirtualizationHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun VirtualizationDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<VirtualizationDetailRowModel>,
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
                VirtualizationDetailRow(row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
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
        DuckIcon(
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
