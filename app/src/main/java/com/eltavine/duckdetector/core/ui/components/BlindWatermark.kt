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

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.sp

/**
 * A blind watermark overlay that repeats device-identity text across the
 * entire screen at very low opacity.
 *
 * The watermark is designed to be unobtrusive during normal use but visible
 * in screenshots, helping to trace leaked images back to a specific device.
 *
 * @param lines   One or more lines of watermark text (e.g. brand, model, fingerprint).
 * @param color   Watermark text colour (default: a dark translucent grey).
 * @param modifier Standard Compose modifier.
 */
@Composable
fun BlindWatermark(
    lines: List<String>,
    color: Color = Color.Black.copy(alpha = 0.06f),
    modifier: Modifier = Modifier,
) {
    if (lines.isEmpty()) return

    val text = lines.joinToString("  ·  ")
    val density = LocalDensity.current
    val fontSizePx = with(density) { 11.sp.toPx() }
    val rowHeightPx = with(density) { 52.sp.toPx() }
    val skewAngle = -20f // degrees – slight diagonal tilt

    Canvas(modifier = modifier.fillMaxSize()) {
        val paint = android.graphics.Paint().apply {
            this.color = color.hashCode() // use raw ARGB
            // Re-apply alpha properly since Color.toArgb() is cleaner
            this.color = android.graphics.Color.argb(
                (color.alpha * 255).toInt().coerceIn(0, 255),
                (color.red * 255).toInt().coerceIn(0, 255),
                (color.green * 255).toInt().coerceIn(0, 255),
                (color.blue * 255).toInt().coerceIn(0, 255),
            )
            textSize = fontSizePx
            isAntiAlias = true
            textSkewX = Math.tan(Math.toRadians(skewAngle.toDouble())).toFloat()
        }

        val textWidth = paint.measureText(text)
        // Repeat text horizontally to fill the width
        val repetitions = if (textWidth > 0) (size.width / textWidth).toInt() + 2 else 1

        var y = -rowHeightPx
        while (y < size.height + rowHeightPx) {
            val offsetX = ((y / rowHeightPx).toInt() % 3) * (textWidth / 3f)
            for (i in 0 until repetitions) {
                val x = i * textWidth + offsetX
                drawContext.canvas.nativeCanvas.drawText(
                    text,
                    x,
                    y,
                    paint,
                )
            }
            y += rowHeightPx
        }
    }
}
