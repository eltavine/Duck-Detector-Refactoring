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

package com.eltavine.duckdetector.core.designsystem.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp

/**
 * Colors for grouped screens, where content sits in containers on a darker page: the arrangement
 * of Apple's grouped lists. Status colors are Apple's system colors, which change between light
 * and dark appearance so each stays legible on its background.
 */
@Immutable
public class DuckPalette internal constructor(
    /** The page behind grouped containers. */
    public val groupedBackground: Color,
    /** A container on [groupedBackground]: a card or a group of rows. */
    public val groupedSurface: Color,
    /** A fill set inside a [groupedSurface], such as a tile of facts. */
    public val groupedInset: Color,
    /** Hairlines between rows of one container. */
    public val separator: Color,
    public val positive: Color,
    public val caution: Color,
    public val critical: Color,
    public val neutral: Color,
)

internal val LocalDuckPalette: ProvidableCompositionLocal<DuckPalette> =
    staticCompositionLocalOf { duckPalette(LightMonochromeScheme, dark = false) }

public object DuckTheme {
    public val palette: DuckPalette
        @Composable @ReadOnlyComposable
        get() = LocalDuckPalette.current
}

// In light appearance the containers are the brightest surface on a tinted page; in dark
// appearance the page is the darkest surface and the containers step up from it.
internal fun duckPalette(scheme: ColorScheme, dark: Boolean): DuckPalette = if (dark) {
    DuckPalette(
        groupedBackground = scheme.surfaceContainerLowest,
        groupedSurface = scheme.surfaceContainerLow,
        groupedInset = scheme.surfaceContainerHigh,
        separator = scheme.outlineVariant.copy(alpha = 0.55f),
        positive = Color(0xFF30D158),
        caution = Color(0xFFFF9F0A),
        critical = Color(0xFFFF453A),
        neutral = Color(0xFF98989D),
    )
} else {
    DuckPalette(
        groupedBackground = scheme.surfaceContainer,
        groupedSurface = scheme.surfaceContainerLowest,
        groupedInset = scheme.surfaceContainer,
        separator = scheme.outlineVariant.copy(alpha = 0.7f),
        positive = Color(0xFF34C759),
        caution = Color(0xFFFF9500),
        critical = Color(0xFFFF3B30),
        neutral = Color(0xFF8E8E93),
    )
}

/** M3E layers from KSU / InstallerX: tonal page, bright grouped items, high inset facts. */
internal fun expressiveDuckPalette(scheme: ColorScheme, dark: Boolean): DuckPalette {
    // The secondary and tertiary roles cannot carry a verdict: Monet derives them from the
    // wallpaper, and the Android 10-11 fallback scheme makes both the same gray.
    val status = duckPalette(scheme, dark)
    return DuckPalette(
        groupedBackground = scheme.surfaceContainer,
        groupedSurface = scheme.surfaceBright,
        groupedInset = scheme.surfaceContainerHigh,
        separator = scheme.outlineVariant.copy(alpha = if (dark) 0.55f else 0.7f),
        positive = status.positive,
        caution = status.caution,
        critical = scheme.error,
        neutral = scheme.onSurfaceVariant,
    )
}

/**
 * A Material tonal container and its content color for a [DuckPalette] status hue, used where
 * Material would otherwise reach for the secondary or tertiary container.
 */
public fun materialStatusTone(accent: Color, scheme: ColorScheme): Pair<Color, Color> =
    lerp(scheme.surfaceContainerHigh, accent, 0.2f) to lerp(accent, scheme.onSurface, 0.55f)
