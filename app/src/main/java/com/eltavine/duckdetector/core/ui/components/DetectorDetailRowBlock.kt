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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance

@Composable
fun DetectorDetailRowBlock(
    label: String,
    value: String,
    status: DetectorStatus,
    modifier: Modifier = Modifier,
    // 让上层在不改版式的前提下给 value 文本附加隐藏手势或语义。
    // Lets callers attach hidden gestures or semantics to the value text without changing the row layout.
    valueModifier: Modifier = Modifier,
    detail: String? = null,
    detailMonospace: Boolean = false,
    statusIcon: ImageVector? = null,
    verticalPadding: Dp = 14.dp,
) {
    val appearance = rememberStatusAppearance(status)

    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = verticalPadding),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        WrapSafeText(
            text = label,
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.labelSmall.copy(
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.5.sp,
            ),
            color = MaterialTheme.colorScheme.primary.copy(alpha = 0.9f),
            textAlign = TextAlign.Center,
        )
        Row(
            verticalAlignment = Alignment.Top,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = statusIcon ?: appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier
                    .padding(top = 1.dp)
                    .size(16.dp),
            )
            WrapSafeText(
                text = value,
                modifier = valueModifier,
                style = MaterialTheme.typography.labelLarge,
                color = appearance.iconTint,
                textAlign = TextAlign.Center,
            )
        }
        detail?.takeIf { it.isNotBlank() }?.let { resolvedDetail ->
            WrapSafeText(
                text = resolvedDetail,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = if (detailMonospace) FontFamily.Monospace else FontFamily.Default,
                ),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
