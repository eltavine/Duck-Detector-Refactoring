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

package com.eltavine.duckdetector.features.dangerousapps.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.ContextLine
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.dangerousapps.ui.DangerousAppsTargetsDialog
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsHeaderFactModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsHiddenPackageItemModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsHmaAlertModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsPackageItemModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DangerousAppsDetectorCard(
    model: DangerousAppsCardModel,
    modifier: Modifier = Modifier,
) {
    var showTargetsDialog by rememberSaveable { mutableStateOf(false) }

    if (showTargetsDialog) {
        DangerousAppsTargetsDialog(
            targets = model.targetApps,
            onDismiss = { showTargetsDialog = false },
        )
    }

    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Apps,
        modifier = modifier,
        headerFacts = {
            DangerousAppsOverview(model = model)
        },
        footerActions = {
            OutlinedButton(
                onClick = { showTargetsDialog = true },
            ) {
                Icon(
                    imageVector = Icons.Rounded.Apps,
                    contentDescription = null,
                )
                WrapSafeText(
                    text = "View target apps (${model.targetApps.size})",
                    modifier = Modifier.padding(start = 8.dp),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
        },
    ) {
        model.hmaAlert?.let { hmaAlert ->
            DangerousAppsHmaSection(
                alert = hmaAlert,
            )
        }

        DetectorSectionFrame(
            title = "Packages",
            icon = Icons.Rounded.Shield,
        ) {
            DangerousAppsPackageSection(model = model)
        }

        DetectorSectionFrame(
            title = "Context",
            icon = Icons.Rounded.Search,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                model.context.forEach { contextItem ->
                    ContextLine(item = contextItem)
                }
            }
        }
    }
}

@Composable
private fun DangerousAppsOverview(
    model: DangerousAppsCardModel,
) {
    val targets = model.headerFacts.firstOrNull { it.label == "Targets" } ?: return
    val packageManager = model.headerFacts.firstOrNull { it.label == "PM" } ?: return
    val hits = model.headerFacts.firstOrNull { it.label == "Hits" } ?: return
    val hidden = model.headerFacts.firstOrNull { it.label == "Hidden" } ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        DangerousAppsFactPairCard(
            primary = targets,
            secondary = packageManager,
            modifier = Modifier.weight(1f),
        )
        DangerousAppsFactPairCard(
            primary = hits,
            secondary = hidden,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun DangerousAppsFactPairCard(
    primary: DangerousAppsHeaderFactModel,
    secondary: DangerousAppsHeaderFactModel,
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
            DangerousAppsFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            DangerousAppsFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun DangerousAppsFactPairRow(
    fact: DangerousAppsHeaderFactModel,
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
private fun DangerousAppsHmaSection(
    alert: DangerousAppsHmaAlertModel,
) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.42f),
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.error.copy(alpha = 0.12f),
                    shape = ShapeTokens.CornerLarge,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VisibilityOff,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier
                            .padding(9.dp)
                            .size(18.dp),
                    )
                }
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    WrapSafeText(
                        text = alert.title,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    WrapSafeText(
                        text = alert.summary,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                alert.hiddenPackages.forEachIndexed { index, item ->
                    DangerousAppsHiddenPackageRow(item = item)
                    if (index < alert.hiddenPackages.lastIndex) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.error.copy(alpha = 0.14f),
                            thickness = 1.dp,
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DangerousAppsHiddenPackageRow(
    item: DangerousAppsHiddenPackageItemModel,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        WrapSafeText(
            text = item.appName,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        WrapSafeText(
            text = item.packageName,
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item.methods.forEach { method ->
                DangerousAppsMethodChip(
                    label = method,
                    warningTone = true,
                )
            }
        }
    }
}

@Composable
private fun DangerousAppsPackageSection(
    model: DangerousAppsCardModel,
) {
    when {
        model.packageItems.isEmpty() -> {
            Surface(
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                shape = ShapeTokens.CornerLargeIncreased,
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 14.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    WrapSafeText(
                        text = "No package hits",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = model.summary,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        else -> {
            Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                model.packageItems.forEachIndexed { index, item ->
                    DangerousAppsPackageRow(item = item)
                    if (index < model.packageItems.lastIndex) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.18f),
                            thickness = 1.dp,
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DangerousAppsPackageRow(
    item: DangerousAppsPackageItemModel,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        WrapSafeText(
            text = item.appName,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
        WrapSafeText(
            text = item.packageName,
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item.methods.forEach { method ->
                DangerousAppsMethodChip(label = method)
            }
        }
    }
}

@Composable
private fun DangerousAppsMethodChip(
    label: String,
    warningTone: Boolean = false,
) {
    val containerColor = if (warningTone) {
        MaterialTheme.colorScheme.error.copy(alpha = 0.08f)
    } else {
        MaterialTheme.colorScheme.surfaceContainerHighest
    }
    val iconTint = if (warningTone) {
        MaterialTheme.colorScheme.error
    } else {
        MaterialTheme.colorScheme.primary
    }

    Surface(
        color = containerColor,
        shape = ShapeTokens.CornerFull,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.Search,
                contentDescription = null,
                tint = iconTint,
                modifier = Modifier.size(14.dp),
            )
            WrapSafeText(
                text = label,
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}
