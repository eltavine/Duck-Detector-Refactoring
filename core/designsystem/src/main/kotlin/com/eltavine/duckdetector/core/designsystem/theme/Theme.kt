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

package com.eltavine.duckdetector.core.designsystem.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.materialkolor.PaletteStyle
import com.materialkolor.dynamiccolor.ColorSpec
import com.materialkolor.rememberDynamicColorScheme
import io.github.xiaotong6666.uihelper.mode.AdaptiveInteractionRuntime
import io.github.xiaotong6666.uihelper.mode.AdaptiveTheme
import io.github.xiaotong6666.uihelper.mode.materialCompatibilityColorSchemeFromMiuix
import io.github.xiaotong6666.uihelper.mode.UiMode

/** Distinct native MIUIX and dynamic Material Expressive skins over the same UI state. */
@Composable
public fun DuckDetectorTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    uiMode: UiMode = UiMode.Miuix,
    content: @Composable () -> Unit,
) {
    val baseScheme = if (darkTheme) DarkMonochromeScheme else LightMonochromeScheme
    val view = LocalView.current
    val context = LocalContext.current

    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            WindowCompat.setDecorFitsSystemWindows(window, false)
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars =
                !darkTheme
        }
    }

    val appMaterialScheme = if (uiMode == UiMode.Material) {
        val seed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (darkTheme) {
                dynamicDarkColorScheme(context).primary
            } else {
                dynamicLightColorScheme(context).primary
            }
        } else {
            baseScheme.primary
        }
        rememberDynamicColorScheme(
            seedColor = seed,
            isDark = darkTheme,
            style = PaletteStyle.TonalSpot,
            specVersion = ColorSpec.SpecVersion.SPEC_2025,
        )
    } else null
    AdaptiveTheme(uiMode = uiMode, darkTheme = darkTheme, materialColorScheme = appMaterialScheme) {
        // Keep MIUIX's own colors. Material uses the M3E dynamic-color pipeline
        // when available and uses the existing palette as the Android 10-11 fallback.
        val colorScheme = if (uiMode == UiMode.Miuix) {
            materialCompatibilityColorSchemeFromMiuix(baseScheme)
        } else requireNotNull(appMaterialScheme)
        val palette = remember(colorScheme, darkTheme, uiMode) {
            if (uiMode == UiMode.Miuix) duckPalette(colorScheme, darkTheme)
            else expressiveDuckPalette(colorScheme, darkTheme)
        }

        // A single stable theme subtree is essential: switching between two separate theme
        // branches disposes DuckDetectorApp and can restart scans / reset the selected tab.
        // MIUIX owns its native components, colors and Folme motion; this Material layer is
        // only for the remaining Compose Material components and cross-skin fallbacks.
        MaterialExpressiveTheme(
            colorScheme = colorScheme,
            typography = if (uiMode == UiMode.Material) ExpressiveTypography else Typography,
            shapes = if (uiMode == UiMode.Material) ExpressiveShapes else Shapes,
            motionScheme = if (uiMode == UiMode.Material) MotionScheme.expressive() else MotionScheme.standard(),
        ) {
            AdaptiveInteractionRuntime {
                CompositionLocalProvider(
                    LocalDuckPalette provides palette,
                    content = content,
                )
            }
        }
    }
}
