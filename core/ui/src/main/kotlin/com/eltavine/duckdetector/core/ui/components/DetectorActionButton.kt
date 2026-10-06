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

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckButtonDefaults
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveButton
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIcon

/**
 * An action at the foot of a detector card. The [prominent] one is washed in the accent color;
 * the others sit on the card's inset fill, so a row of them reads as one quiet group.
 */
@Composable
public fun DetectorActionButton(
    label: String,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    prominent: Boolean = false,
    singleLineLabel: Boolean = false,
) {
    val content: @Composable RowScope.() -> Unit = {
        AdaptiveIcon(imageVector = icon, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(modifier = Modifier.width(8.dp))
        WrapSafeText(
            text = label,
            style = DuckTypography.ActionLabel,
            maxLines = if (singleLineLabel) 1 else Int.MAX_VALUE,
            overflow = if (singleLineLabel) TextOverflow.Ellipsis else TextOverflow.Clip,
        )
    }
    AdaptiveContent(
        material = {
            if (prominent) {
                Button(
                    onClick = onClick,
                    modifier = modifier,
                    enabled = enabled,
                    colors = DuckButtonDefaults.filledColors(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                    content = content,
                )
            } else {
                FilledTonalButton(
                    onClick = onClick,
                    modifier = modifier,
                    enabled = enabled,
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                    content = content,
                )
            }
        },
        miuix = {
            AdaptiveButton(
                onClick = onClick,
                modifier = modifier,
                enabled = enabled,
                prominent = prominent,
                materialContentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                content = content,
            )
        },
    )
}
