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

package com.eltavine.duckdetector.features.rootmanagers.ui.card

import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Search
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorFact
import com.eltavine.duckdetector.core.ui.components.DetectorFactPair
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionGroup
import com.eltavine.duckdetector.core.ui.components.highestSectionSeverity
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersCardModel
import com.eltavine.duckdetector.features.rootmanagers.presentation.model.RootManagersDetailRowModel
import com.eltavine.duckdetector.features.rootmanagers.ui.R
import com.eltavine.duckdetector.core.ui.R as CoreUiR

@Composable
internal fun RootManagersDetectorCard(
    model: RootManagersCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Policy,
        modifier = modifier,
        headerFacts = { RootManagersOverview(model.headerFacts) },
    ) {
        DetectorSectionGroup {
            item(visible = model.entryRows.isNotEmpty()) {
                RootManagersRowSection(
                    sectionKey = "rootmanagers.matches",
                    title = stringResource(R.string.root_managers_section_matches),
                    icon = Icons.Rounded.Search,
                    rows = model.entryRows,
                    showDivider = model.profileRows.isNotEmpty() || model.impactRows.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.profileRows.isNotEmpty()) {
                RootManagersRowSection(
                    sectionKey = "rootmanagers.profiles",
                    title = stringResource(R.string.root_managers_section_profiles),
                    icon = Icons.Rounded.Policy,
                    rows = model.profileRows,
                    showDivider = model.impactRows.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.impactRows.isNotEmpty()) {
                RootManagersRowSection(
                    sectionKey = "rootmanagers.impact",
                    title = stringResource(R.string.root_managers_section_impact),
                    icon = Icons.Rounded.CrisisAlert,
                    rows = model.impactRows,
                    showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.methodRows.isNotEmpty()) {
                RootManagersRowSection(
                    sectionKey = "rootmanagers.methods",
                    title = stringResource(R.string.root_managers_section_detection_methods),
                    icon = Icons.Rounded.Search,
                    rows = model.methodRows,
                    showDivider = model.scanRows.isNotEmpty(),
                )
            }
            item(visible = model.scanRows.isNotEmpty()) {
                RootManagersRowSection(
                    sectionKey = "rootmanagers.scan",
                    title = stringResource(R.string.root_managers_section_scan),
                    icon = Icons.Rounded.Info,
                    rows = model.scanRows,
                    showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun RootManagersRowSection(
    sectionKey: String,
    title: String,
    icon: ImageVector,
    rows: List<RootManagersDetailRowModel>,
    showDivider: Boolean,
) {
    if (rows.isEmpty()) {
        return
    }
    DetectorSectionFrame(
        stateKey = sectionKey,
        title = title,
        icon = icon,
        severity = highestSectionSeverity(rows.map { row -> row.status }),
        showDivider = showDivider,
    ) {
        rows.forEachIndexed { index, row ->
            RootManagersDetailRow(row)
            if (index < rows.lastIndex) {
                DetectorHairline()
            }
        }
    }
}

@Composable
private fun RootManagersDetailRow(
    row: RootManagersDetailRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.root_managers_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val copyText = row.hiddenCopyText
    val rowModifier = if (copyText != null) {
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                // Keep every node's full detail off the visible card but one double tap away for
                // development, matching the other detectors' hidden-copy rows.
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
private fun RootManagersOverview(facts: List<RootManagersDetailRowModel>) {
    if (facts.size != 4) return
    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        facts.chunked(2).forEach { pair ->
            DetectorFactPair(
                primary = DetectorFact(pair[0].label, pair[0].value, pair[0].status),
                secondary = DetectorFact(pair[1].label, pair[1].value, pair[1].status),
                modifier = Modifier.weight(1f),
            )
        }
    }
}
