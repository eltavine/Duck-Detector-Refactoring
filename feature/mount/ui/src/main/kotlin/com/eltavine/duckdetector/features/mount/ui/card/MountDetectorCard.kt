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

package com.eltavine.duckdetector.features.mount.ui.card

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountTree
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.FolderOpen
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Storage
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
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
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.mount.ui.R
import com.eltavine.duckdetector.features.mount.presentation.model.MountCardModel
import com.eltavine.duckdetector.features.mount.presentation.model.MountDetailRowModel
import com.eltavine.duckdetector.features.mount.presentation.model.MountHeaderFact
import com.eltavine.duckdetector.features.mount.presentation.model.MountHeaderFactModel
import com.eltavine.duckdetector.features.mount.presentation.model.MountImpactItemModel
import com.eltavine.duckdetector.core.ui.R as CoreUiR

@Composable
internal fun MountDetectorCard(
    model: MountCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Storage,
        modifier = modifier,
        headerFacts = {
            MountCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.procMountViewRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_isolated_process),
                icon = Icons.Rounded.AccountTree,
                rows = model.procMountViewRows,
                showDivider = model.artifactRows.isNotEmpty() || model.runtimeRows.isNotEmpty() ||
                    model.filesystemRows.isNotEmpty() || model.consistencyRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.artifactRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_root_artifacts),
                icon = Icons.Rounded.FolderOpen,
                rows = model.artifactRows,
                showDivider = model.runtimeRows.isNotEmpty() || model.filesystemRows.isNotEmpty() ||
                    model.consistencyRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.runtimeRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_runtime_mounts),
                icon = Icons.Rounded.Storage,
                rows = model.runtimeRows,
                showDivider = model.filesystemRows.isNotEmpty() || model.consistencyRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.filesystemRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_filesystem),
                icon = Icons.Rounded.Memory,
                rows = model.filesystemRows,
                showDivider = model.consistencyRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.consistencyRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_namespace_consistency),
                icon = Icons.Rounded.AccountTree,
                rows = model.consistencyRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                MountImpactSection(
                title = stringResource(R.string.mount_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                MountDetailSection(
                title = stringResource(R.string.mount_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun MountCollapsedOverview(
    model: MountCardModel,
) {
    val critical = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.CRITICAL } ?: return
    val review = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.REVIEW } ?: return
    val coverage = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.COVERAGE } ?: return
    val native = model.headerFacts.firstOrNull { it.fact == MountHeaderFact.NATIVE } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        MountFactPairCard(
            primary = critical,
            secondary = review,
            modifier = Modifier.weight(1f),
        )
        MountFactPairCard(
            primary = coverage,
            secondary = native,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun MountFactPairCard(
    primary: MountHeaderFactModel,
    secondary: MountHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun MountHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun MountDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<MountDetailRowModel>,
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
                MountDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun MountDetailRow(
    row: MountDetailRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.mount_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val copyText = row.hiddenCopyText
    val rowModifier = if (copyText != null) {
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                copyPlainTextToClipboard(context, clipboardLabel, copyText, copiedToast)
            },
        )
    } else {
        Modifier
    }
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        modifier = rowModifier,
        detail = row.detail,
        detailMonospace = row.detailMonospace,
    )
}

@Composable
private fun MountImpactSection(
    title: String,
    icon: ImageVector,
    items: List<MountImpactItemModel>,
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
                MountImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun MountImpactRow(
    item: MountImpactItemModel,
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
