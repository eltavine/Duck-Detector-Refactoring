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

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.graphics.Shape
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode

/** Resolve native per-skin shapes without applying MIUIX continuous corners to Material UI. */
public object AdaptiveShapeTokens {
    public val CornerMedium: Shape
        @Composable @ReadOnlyComposable get() =
            if (LocalUiMode.current == UiMode.Miuix) ShapeTokens.CornerMedium else MaterialTheme.shapes.medium

    public val CornerLarge: Shape
        @Composable @ReadOnlyComposable get() =
            if (LocalUiMode.current == UiMode.Miuix) ShapeTokens.CornerLarge else MaterialTheme.shapes.large

    public val CornerExtraLarge: Shape
        @Composable @ReadOnlyComposable get() =
            if (LocalUiMode.current == UiMode.Miuix) ShapeTokens.CornerExtraLarge else MaterialTheme.shapes.extraLarge
}
