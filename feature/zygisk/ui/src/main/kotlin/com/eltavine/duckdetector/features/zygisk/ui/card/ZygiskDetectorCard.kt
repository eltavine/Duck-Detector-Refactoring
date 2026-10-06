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

package com.eltavine.duckdetector.features.zygisk.ui.card

import com.eltavine.duckdetector.features.zygisk.ui.R
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.automirrored.rounded.MenuBook
import androidx.compose.material.icons.rounded.CrisisAlert
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
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskCardModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskDetailRowModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskHeaderFact
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskHeaderFactModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskImpactItemModel
import com.eltavine.duckdetector.features.zygisk.presentation.model.ZygiskRowIcon

@Composable
internal fun ZygiskDetectorCard(
    model: ZygiskCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Code,
        modifier = modifier,
        headerFacts = {
            ZygiskCollapsedOverview(model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.stateRows.isNotEmpty()) {
                ZygiskDetailSection(
                    stringResource(R.string.zygisk_section_security_state),
                    Icons.Rounded.Info,
                    model.stateRows,
                    showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() ||
                        model.signalRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.impactItems.isNotEmpty()) {
                ZygiskImpactSection(
                    stringResource(R.string.zygisk_section_impact),
                    Icons.Rounded.CrisisAlert,
                    model.impactItems,
                    showDivider = model.methodRows.isNotEmpty() || model.signalRows.isNotEmpty() ||
                        model.references.isNotEmpty(),
                )
            }
            item(visible = model.methodRows.isNotEmpty()) {
                ZygiskDetailSection(
                    stringResource(R.string.zygisk_section_detection_methods),
                    Icons.Rounded.Search,
                    model.methodRows,
                    showDivider = model.signalRows.isNotEmpty() || model.references.isNotEmpty(),
                )
            }
            item(visible = model.signalRows.isNotEmpty()) {
                ZygiskDetailSection(
                    stringResource(R.string.zygisk_section_signals),
                    Icons.Rounded.Memory,
                    model.signalRows,
                    showDivider = model.references.isNotEmpty(),
                )
            }
            item(visible = model.references.isNotEmpty()) {
                DetectorSectionFrame(
                    title = stringResource(R.string.zygisk_section_references),
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
private fun ZygiskCollapsedOverview(
    model: ZygiskCardModel,
) {
    val state = model.headerFacts.firstOrNull { it.fact == ZygiskHeaderFact.STATE } ?: return
    val confidence = model.headerFacts.firstOrNull { it.fact == ZygiskHeaderFact.CONFIDENCE } ?: return
    val fdTrap = model.headerFacts.firstOrNull { it.fact == ZygiskHeaderFact.FD_TRAP } ?: return
    val native = model.headerFacts.firstOrNull { it.fact == ZygiskHeaderFact.NATIVE } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        ZygiskFactPairCard(
            primary = state,
            secondary = confidence,
            modifier = Modifier.weight(1f),
        )
        ZygiskFactPairCard(
            primary = fdTrap,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun ZygiskFactPairCard(
    primary: ZygiskHeaderFactModel,
    secondary: ZygiskHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun ZygiskHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun ZygiskDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<ZygiskDetailRowModel>,
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
                ZygiskDetailRow(row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun ZygiskDetailRow(
    row: ZygiskDetailRowModel,
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
private fun ZygiskImpactSection(
    title: String,
    icon: ImageVector,
    items: List<ZygiskImpactItemModel>,
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
                ZygiskImpactRow(item)
            }
        }
    }
}

@Composable
private fun ZygiskImpactRow(
    item: ZygiskImpactItemModel,
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
    row: ZygiskDetailRowModel,
    fallback: ImageVector,
): ImageVector {
    return when (row.icon) {
        ZygiskRowIcon.CROSS_PROCESS -> Icons.Rounded.SyncAlt
        ZygiskRowIcon.LINKER -> Icons.Rounded.FolderZip
        ZygiskRowIcon.MEMORY -> Icons.Rounded.Memory
        null -> fallback
    }
}
