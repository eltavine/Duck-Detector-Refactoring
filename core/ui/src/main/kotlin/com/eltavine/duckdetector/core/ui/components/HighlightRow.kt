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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import io.github.xiaotong6666.uihelper.adaptive.adaptiveInsetSurfaceColor
import com.eltavine.duckdetector.core.ui.model.HighlightItemModel
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceBackground
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue

@Composable
public fun HighlightRow(
    item: HighlightItemModel,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(item.status)

    Row(
        modifier = modifier
            .fillMaxWidth()
            .adaptiveSurfaceBackground(
                materialColor = DuckTheme.palette.groupedInset,
                materialShape = MaterialTheme.shapes.large,
                miuixColor = adaptiveInsetSurfaceColor(),
                miuixCornerRadius = 16.dp,
            )
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AdaptiveIcon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = appearance.iconTint,
            modifier = Modifier
                .padding(top = 1.dp)
                .size(18.dp),
        )
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            WrapSafeText(
                text = item.title,
                modifier = Modifier.fillMaxWidth(),
                style = adaptiveValue(
                    material = DuckTypography.CalloutEmphasized,
                    miuix = DuckTypography.PanelTitle,
                ),
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = item.detail,
                modifier = Modifier.fillMaxWidth(),
                style = DuckTypography.PanelSupporting,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            CompactStatusBadge(status = item.status, modifier = Modifier.padding(top = 4.dp))
        }
    }
}
