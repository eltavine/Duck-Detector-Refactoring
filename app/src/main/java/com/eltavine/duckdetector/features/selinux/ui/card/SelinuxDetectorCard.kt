/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.features.selinux.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.MenuBook
import androidx.compose.material.icons.automirrored.rounded.FactCheck
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxCardModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxDetailRowModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxHeaderFactModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxImpactItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun SelinuxDetectorCard(
    model: SelinuxCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Security,
        modifier = modifier,
        headerFacts = {
            SelinuxCollapsedOverview(model = model)
        },
    ) {
        if (model.stateRows.isNotEmpty()) {
            SelinuxDetailSection(
                title = "Security state",
                icon = Icons.Rounded.AdminPanelSettings,
                rows = model.stateRows,
            )
        }

        if (model.impactItems.isNotEmpty()) {
            SelinuxImpactSection(
                title = "Impact",
                icon = Icons.Rounded.CrisisAlert,
                items = model.impactItems,
            )
        }

        if (model.methodRows.isNotEmpty()) {
            SelinuxDetailSection(
                title = "Detection methods",
                icon = Icons.Rounded.Search,
                rows = model.methodRows,
            )
        }

        if (model.policyRows.isNotEmpty() || model.policyNotes.isNotEmpty()) {
            DetectorSectionFrame(
                title = "Policy analysis",
                icon = Icons.Rounded.Policy,
            ) {
                if (model.policyRows.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                        model.policyRows.forEachIndexed { index, row ->
                            SelinuxDetailRow(row = row)
                            if (index < model.policyRows.lastIndex) {
                                HorizontalDivider(
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                                    thickness = 1.dp,
                                )
                            }
                        }
                    }
                }

                if (model.policyNotes.isNotEmpty()) {
                    if (model.policyRows.isNotEmpty()) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.22f),
                            thickness = 1.dp,
                        )
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        model.policyNotes.forEach { note ->
                            SelinuxImpactRow(item = note)
                        }
                    }
                }
            }
        }

        if (model.auditRows.isNotEmpty() || model.auditNotes.isNotEmpty()) {
            DetectorSectionFrame(
                title = "Audit integrity",
                icon = Icons.AutoMirrored.Rounded.FactCheck,
            ) {
                if (model.auditRows.isNotEmpty()) {
                    Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                        model.auditRows.forEachIndexed { index, row ->
                            SelinuxDetailRow(row = row)
                            if (index < model.auditRows.lastIndex) {
                                HorizontalDivider(
                                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                                    thickness = 1.dp,
                                )
                            }
                        }
                    }
                }

                if (model.auditNotes.isNotEmpty()) {
                    if (model.auditRows.isNotEmpty()) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.22f),
                            thickness = 1.dp,
                        )
                    }
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        model.auditNotes.forEach { note ->
                            SelinuxImpactRow(item = note)
                        }
                    }
                }
            }
        }

        if (model.deviceRows.isNotEmpty()) {
            SelinuxDetailSection(
                title = "Device info",
                icon = Icons.Rounded.Info,
                rows = model.deviceRows,
            )
        }

        if (model.references.isNotEmpty()) {
            DetectorSectionFrame(
                title = "Reference",
                icon = Icons.AutoMirrored.Rounded.MenuBook,
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

@Composable
private fun SelinuxCollapsedOverview(
    model: SelinuxCardModel,
) {
    val mode = model.headerFacts.firstOrNull { it.label == "Mode" } ?: return
    val policy = model.headerFacts.firstOrNull { it.label == "Policy" } ?: return
    val audit = model.headerFacts.firstOrNull { it.label == "Audit" } ?: return
    val context = model.headerFacts.firstOrNull { it.label == "Context" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        SelinuxFactPairCard(
            primary = mode,
            secondary = policy,
            modifier = Modifier.weight(1f),
        )
        SelinuxFactPairCard(
            primary = audit,
            secondary = context,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun SelinuxFactPairCard(
    primary: SelinuxHeaderFactModel,
    secondary: SelinuxHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            SelinuxFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            SelinuxFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun SelinuxFactPairRow(
    fact: SelinuxHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = fact.label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun SelinuxDetailSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    rows: List<SelinuxDetailRowModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            rows.forEachIndexed { index, row ->
                SelinuxDetailRow(row = row)
                if (index < rows.lastIndex) {
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                        thickness = 1.dp,
                    )
                }
            }
        }
    }
}

@Composable
private fun SelinuxDetailRow(
    row: SelinuxDetailRowModel,
) {
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        detail = row.detail,
    )
}

@Composable
private fun SelinuxImpactSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    items: List<SelinuxImpactItemModel>,
) {
    DetectorSectionFrame(
        title = title,
        icon = icon,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            items.forEach { item ->
                SelinuxImpactRow(item = item)
            }
        }
    }
}

@Composable
private fun SelinuxImpactRow(
    item: SelinuxImpactItemModel,
) {
    val appearance = rememberStatusAppearance(item.status)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Icon(
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
