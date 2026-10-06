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

import androidx.compose.foundation.shape.CornerBasedShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

internal val Shapes: Shapes = Shapes(
    extraSmall = ContinuousCornerShape(4.dp),
    small = ContinuousCornerShape(8.dp),
    medium = ContinuousCornerShape(12.dp),
    large = ContinuousCornerShape(16.dp),
    extraLarge = ContinuousCornerShape(28.dp),
)

/** Material Expressive shapes. Keep the legacy continuous shapes for MIUIX fallbacks. */
internal val ExpressiveShapes: Shapes = Shapes()

public object ShapeTokens {
    public val CornerMedium: CornerBasedShape = ContinuousCornerShape(12.dp)
    public val CornerLarge: CornerBasedShape = ContinuousCornerShape(16.dp)
    public val CornerLargeIncreased: CornerBasedShape = ContinuousCornerShape(20.dp)
    public val CornerExtraLarge: CornerBasedShape = ContinuousCornerShape(24.dp)
    public val CornerExtraLargeIncreased: CornerBasedShape = ContinuousCornerShape(28.dp)
    public val CornerFull: RoundedCornerShape = RoundedCornerShape(50)
}
