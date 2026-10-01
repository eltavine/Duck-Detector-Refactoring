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
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import kotlin.math.max
import kotlin.math.min
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DuckPaletteTest {
    @Test
    fun materialStatusHuesStayApartOnTheFallbackScheme() {
        for ((scheme, dark) in FallbackSchemes) {
            val palette = expressiveDuckPalette(scheme, dark)

            assertNotEquals(palette.positive, palette.caution)
            assertNotEquals(palette.caution, palette.critical)
            assertNotEquals(palette.positive, palette.neutral)
        }
    }

    @Test
    fun materialStatusHuesIgnoreTheWallpaperAccentRoles() {
        for ((scheme, dark) in FallbackSchemes) {
            val wallpaper = scheme.copy(secondary = Color.Magenta, tertiary = Color.Cyan)

            val palette = expressiveDuckPalette(wallpaper, dark)

            assertEquals(duckPalette(scheme, dark).positive, palette.positive)
            assertEquals(duckPalette(scheme, dark).caution, palette.caution)
        }
    }

    @Test
    fun materialStatusToneKeepsItsLabelLegible() {
        val schemes = FallbackSchemes + listOf(lightColorScheme() to false, darkColorScheme() to true)
        for ((scheme, dark) in schemes) {
            val palette = expressiveDuckPalette(scheme, dark)
            for (accent in listOf(palette.positive, palette.caution)) {
                val (container, content) = materialStatusTone(accent, scheme)

                val ratio = contrast(container, content)
                assertTrue("contrast $ratio for $accent, dark=$dark", ratio >= 4.5f)
            }
        }
    }

    private fun contrast(a: Color, b: Color): Float {
        val lighter = max(a.luminance(), b.luminance())
        val darker = min(a.luminance(), b.luminance())
        return (lighter + 0.05f) / (darker + 0.05f)
    }

    private companion object {
        val FallbackSchemes: List<Pair<ColorScheme, Boolean>> = listOf(
            LightMonochromeScheme to false,
            DarkMonochromeScheme to true,
        )
    }
}
