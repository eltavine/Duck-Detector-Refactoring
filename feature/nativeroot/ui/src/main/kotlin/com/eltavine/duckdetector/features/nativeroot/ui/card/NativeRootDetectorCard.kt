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

package com.eltavine.duckdetector.features.nativeroot.ui.card

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
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
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.nativeroot.ui.R
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootCardModel
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootDetailRowModel
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootHeaderFact
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootHeaderFactModel
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootImpactItemModel
import com.eltavine.duckdetector.core.ui.R as CoreUiR

@Composable
internal fun NativeRootDetectorCard(
    model: NativeRootCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.BugReport,
        modifier = modifier,
        headerFacts = {
            NativeRootCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.nativeRows.isNotEmpty()) {
                NativeRootDetailSection(
                title = stringResource(R.string.nativeroot_section_native_probes),
                icon = Icons.Rounded.Security,
                rows = model.nativeRows,
                showDivider = model.runtimeRows.isNotEmpty() || model.kernelRows.isNotEmpty() ||
                    model.propertyRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.runtimeRows.isNotEmpty()) {
                NativeRootDetailSection(
                title = stringResource(R.string.nativeroot_section_runtime_artifacts),
                icon = Icons.Rounded.Shield,
                rows = model.runtimeRows,
                showDivider = model.kernelRows.isNotEmpty() || model.propertyRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.kernelRows.isNotEmpty()) {
                NativeRootDetailSection(
                title = stringResource(R.string.nativeroot_section_kernel_traces),
                icon = Icons.Rounded.Memory,
                rows = model.kernelRows,
                showDivider = model.propertyRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.propertyRows.isNotEmpty()) {
                NativeRootDetailSection(
                title = stringResource(R.string.nativeroot_section_property_residue),
                icon = Icons.Rounded.Info,
                rows = model.propertyRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                NativeRootImpactSection(
                title = stringResource(R.string.nativeroot_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                NativeRootDetailSection(
                title = stringResource(R.string.nativeroot_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                NativeRootDetailSection(
                title = stringResource(R.string.nativeroot_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun NativeRootCollapsedOverview(
    model: NativeRootCardModel,
) {
    val flags = model.headerFacts.firstOrNull { it.fact == NativeRootHeaderFact.FLAGS } ?: return
    val direct = model.headerFacts.firstOrNull { it.fact == NativeRootHeaderFact.DIRECT } ?: return
    val kernel = model.headerFacts.firstOrNull { it.fact == NativeRootHeaderFact.KERNEL } ?: return
    val runtime = model.headerFacts.firstOrNull { it.fact == NativeRootHeaderFact.RUNTIME } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        NativeRootFactPairCard(
            primary = flags,
            secondary = direct,
            modifier = Modifier.weight(1f),
        )
        NativeRootFactPairCard(
            primary = kernel,
            secondary = runtime,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun NativeRootFactPairCard(
    primary: NativeRootHeaderFactModel,
    secondary: NativeRootHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun NativeRootHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun NativeRootDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<NativeRootDetailRowModel>,
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
                NativeRootDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun NativeRootDetailRow(
    row: NativeRootDetailRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.native_root_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val copyText = row.hiddenCopyText
    val rowModifier = if (copyText != null) {
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                // Keep diagnostics hidden from the visible UI but one double tap away when a
                // device report has to be shared with maintainers.
                // 将诊断隐藏在可见 UI 之外；需要分享设备报告时双击即可复制。
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
private fun NativeRootImpactSection(
    title: String,
    icon: ImageVector,
    items: List<NativeRootImpactItemModel>,
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
                NativeRootImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun NativeRootImpactRow(
    item: NativeRootImpactItemModel,
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
