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

package com.eltavine.duckdetector.features.deviceinfo.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Android
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.PhoneAndroid
import androidx.compose.material.icons.rounded.SettingsEthernet
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoHeaderFactModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoRowModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoSectionModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@Composable
fun DeviceInfoCard(
    model: DeviceInfoCardModel,
    modifier: Modifier = Modifier,
) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.PhoneAndroid,
        modifier = modifier,
        headerFacts = {
            DeviceInfoHeader(model.headerFacts)
        },
    ) {
        model.sections.forEach { section ->
            DeviceInfoSection(
                model = section,
            )
        }
    }
}

@Composable
private fun DeviceInfoHeader(
    facts: List<DeviceInfoHeaderFactModel>,
) {
    val brand = facts.getOrNull(0) ?: return
    val model = facts.getOrNull(1) ?: return
    val android = facts.getOrNull(2) ?: return
    val sdk = facts.getOrNull(3) ?: return

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        DeviceInfoFactCard(
            primary = brand,
            secondary = model,
            modifier = Modifier.weight(1f),
        )
        DeviceInfoFactCard(
            primary = android,
            secondary = sdk,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun DeviceInfoFactCard(
    primary: DeviceInfoHeaderFactModel,
    secondary: DeviceInfoHeaderFactModel,
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
            DeviceInfoFactRow(primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                thickness = 1.dp,
            )
            DeviceInfoFactRow(secondary)
        }
    }
}

@Composable
private fun DeviceInfoFactRow(
    fact: DeviceInfoHeaderFactModel,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        WrapSafeText(
            text = fact.label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun DeviceInfoSection(
    model: DeviceInfoSectionModel,
) {
    DetectorSectionFrame(
        title = model.title,
        icon = sectionIcon(model.title),
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            model.rows.forEachIndexed { index, row ->
                DeviceInfoRow(row)
                if (index < model.rows.lastIndex) {
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.16f),
                        thickness = 1.dp,
                    )
                }
            }
        }
    }
}

@Composable
private fun DeviceInfoRow(
    row: DeviceInfoRowModel,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            WrapSafeText(
                text = row.label,
                modifier = Modifier.weight(0.34f),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            WrapSafeText(
                text = row.value,
                modifier = Modifier.weight(0.66f),
                style = MaterialTheme.typography.bodyMedium.copy(
                    fontFamily = if (row.detailMonospace) FontFamily.Monospace else FontFamily.Default,
                ),
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

private fun sectionIcon(
    title: String,
): ImageVector {
    return when (title) {
        "Identity" -> Icons.Rounded.Badge
        "Build" -> Icons.Rounded.Dns
        "Android" -> Icons.Rounded.Android
        "Runtime" -> Icons.Rounded.Memory
        "Context" -> Icons.Rounded.SettingsEthernet
        else -> Icons.Rounded.Info
    }
}
