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

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import io.github.xiaotong6666.uihelper.adaptive.adaptiveInsetSurfaceColor
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveHorizontalDivider
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceBackground
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode

internal val LocalMaterialDetectorHairlineStartInset = compositionLocalOf<Dp?> { null }

/** One fact of a card's header: a short label over its value, and the status it reports, if any. */
@Immutable
public class DetectorFact(
    public val label: String,
    public val value: String,
    public val status: DetectorStatus? = null,
)

/** Two facts stacked in one tile; detector cards set two tiles side by side under the verdict. */
@Composable
public fun DetectorFactPair(
    primary: DetectorFact,
    secondary: DetectorFact,
    modifier: Modifier = Modifier,
) {
    AdaptiveContent(
        miuix = {
            Column(
                modifier = modifier
                    .fillMaxHeight()
                    .adaptiveSurfaceBackground(
                        materialColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                        materialShape = MaterialTheme.shapes.large,
                        miuixColor = adaptiveInsetSurfaceColor(),
                        miuixCornerRadius = 16.dp,
                    )
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                DetectorFactLine(fact = primary)
                DetectorHairline()
                DetectorFactLine(fact = secondary)
            }
        },
        material = {
            Column(
                modifier = modifier
                    .fillMaxHeight()
                    .background(
                        color = MaterialTheme.colorScheme.surfaceContainerHigh,
                        shape = MaterialTheme.shapes.large,
                    )
                    .padding(horizontal = 14.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                DetectorFactLine(fact = primary)
                DetectorHairline()
                DetectorFactLine(fact = secondary)
            }
        },
    )
}

@Composable
private fun DetectorFactLine(
    fact: DetectorFact,
    showStatusIcon: Boolean = true,
) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(5.dp),
        ) {
            fact.status?.takeIf { showStatusIcon }?.let { status ->
                val appearance = rememberStatusAppearance(status)
                AdaptiveIcon(
                    imageVector = appearance.icon,
                    contentDescription = null,
                    tint = appearance.iconTint,
                    modifier = Modifier.size(13.dp),
                )
            }
            WrapSafeText(
                text = fact.label,
                style = DuckTypography.PanelCaption,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = DuckTypography.PanelTitle,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** A one-pixel rule between rows of the same container, optionally inset from its start. */
@Composable
public fun DetectorHairline(
    modifier: Modifier = Modifier,
    startInset: Dp = 0.dp,
) {
    val resolvedStartInset = if (
        LocalUiMode.current == UiMode.Material &&
        startInset == 0.dp
    ) {
        LocalMaterialDetectorHairlineStartInset.current ?: startInset
    } else {
        startInset
    }
    AdaptiveHorizontalDivider(
        modifier = modifier.padding(start = resolvedStartInset),
        thickness = Dp.Hairline,
        materialColor = DuckTheme.palette.separator,
    )
}
