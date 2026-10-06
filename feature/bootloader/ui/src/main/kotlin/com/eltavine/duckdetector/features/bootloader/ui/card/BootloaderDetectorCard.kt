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

package com.eltavine.duckdetector.features.bootloader.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.automirrored.rounded.FactCheck
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.QuestionMark
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.VerifiedUser
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
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
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderCardAssessment
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderCardModel
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderDetailRowModel
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderHeaderFact
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderHeaderFactModel
import com.eltavine.duckdetector.features.bootloader.presentation.model.BootloaderImpactItemModel
import com.eltavine.duckdetector.features.bootloader.ui.R

@Composable
internal fun BootloaderDetectorCard(
    model: BootloaderCardModel,
    modifier: Modifier = Modifier,
) {
    val consistencyDescription = when (model.assessment) {
        BootloaderCardAssessment.AUTHORITATIVE -> null
        BootloaderCardAssessment.CONSISTENCY_REVIEW ->
            stringResource(R.string.bootloader_widevine_consistency_review)
    }
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Lock,
        leadingBadgeIcon = if (model.showConsistencyQuestionIcon) {
            Icons.Rounded.QuestionMark
        } else {
            null
        },
        leadingBadgeStatus = model.assessmentStatus,
        leadingBadgeContentDescription = consistencyDescription,
        modifier = modifier,
        headerFacts = {
            BootloaderCollapsedOverview(model = model)
        },
    ) {
        DetectorSectionGroup {
            item(visible = model.stateRows.isNotEmpty()) {
                BootloaderDetailSection(
                title = stringResource(R.string.bootloader_section_boot_state),
                icon = Icons.Rounded.VerifiedUser,
                rows = model.stateRows,
                showDivider = model.attestationRows.isNotEmpty() || model.propertyRows.isNotEmpty() ||
                    model.consistencyRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.attestationRows.isNotEmpty()) {
                BootloaderDetailSection(
                title = stringResource(R.string.bootloader_section_attestation),
                icon = Icons.Rounded.Key,
                rows = model.attestationRows,
                showDivider = model.propertyRows.isNotEmpty() || model.consistencyRows.isNotEmpty() ||
                    model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.propertyRows.isNotEmpty()) {
                BootloaderDetailSection(
                title = stringResource(R.string.bootloader_section_boot_properties),
                icon = Icons.Rounded.Settings,
                rows = model.propertyRows,
                showDivider = model.consistencyRows.isNotEmpty() || model.impactItems.isNotEmpty() ||
                    model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.consistencyRows.isNotEmpty()) {
                BootloaderDetailSection(
                title = stringResource(R.string.bootloader_section_consistency),
                icon = Icons.AutoMirrored.Rounded.FactCheck,
                rows = model.consistencyRows,
                showDivider = model.impactItems.isNotEmpty() || model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.impactItems.isNotEmpty()) {
                BootloaderImpactSection(
                title = stringResource(R.string.bootloader_section_impact),
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
                showDivider = model.methodRows.isNotEmpty() || model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.methodRows.isNotEmpty()) {
                BootloaderDetailSection(
                title = stringResource(R.string.bootloader_section_detection_methods),
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
                showDivider = model.scanRows.isNotEmpty(),
                )
            }

            item(visible = model.scanRows.isNotEmpty()) {
                BootloaderDetailSection(
                title = stringResource(R.string.bootloader_section_scan_summary),
                icon = Icons.Rounded.Info,
                rows = model.scanRows,
                showDivider = false,
                )
            }
        }
    }
}

@Composable
private fun BootloaderCollapsedOverview(
    model: BootloaderCardModel,
) {
    val state = model.headerFacts.firstOrNull { it.fact == BootloaderHeaderFact.STATE } ?: return
    val proof = model.headerFacts.firstOrNull { it.fact == BootloaderHeaderFact.PROOF } ?: return
    val tier = model.headerFacts.firstOrNull { it.fact == BootloaderHeaderFact.TIER } ?: return
    val trust = model.headerFacts.firstOrNull { it.fact == BootloaderHeaderFact.TRUST } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        BootloaderFactPairCard(
            primary = state,
            secondary = proof,
            modifier = Modifier.weight(1f),
        )
        BootloaderFactPairCard(
            primary = tier,
            secondary = trust,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun BootloaderFactPairCard(
    primary: BootloaderHeaderFactModel,
    secondary: BootloaderHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun BootloaderHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
private fun BootloaderDetailSection(
    title: String,
    icon: ImageVector,
    rows: List<BootloaderDetailRowModel>,
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
                BootloaderDetailRow(row = row)
                if (index < rows.lastIndex) {
                    DetectorHairline()
                }
            }
        }
    }
}

@Composable
private fun BootloaderDetailRow(
    row: BootloaderDetailRowModel,
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
private fun BootloaderImpactSection(
    title: String,
    icon: ImageVector,
    items: List<BootloaderImpactItemModel>,
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
                BootloaderImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun BootloaderImpactRow(
    item: BootloaderImpactItemModel,
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
