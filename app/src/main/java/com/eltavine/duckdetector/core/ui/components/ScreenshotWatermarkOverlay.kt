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
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eltavine.duckdetector.BuildConfig
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale


@Composable
fun ScreenshotWatermarkOverlay(
    modifier: Modifier = Modifier,
    alpha: Float = 0.05f,
    textSizeSp: Float = 11f,
    spacingDp: Float = 180f,
    rotationDegrees: Float = -30f
) {
    val density = LocalDensity.current
    val textSizePx = with(density) { textSizeSp.sp.toPx() }
    val spacingPx = with(density) { spacingDp.dp.toPx() }

    var currentTimeMillis by remember { mutableLongStateOf(System.currentTimeMillis()) }

    LaunchedEffect(Unit) {
        while (true) {
            delay(60_000L) // Update every minute
            currentTimeMillis = System.currentTimeMillis()
        }
    }

    val dateFormat = remember { SimpleDateFormat("MMM d. yy HH:mm", Locale.getDefault()) }
    val timeString = remember(currentTimeMillis) {
        val date = Date(currentTimeMillis)
        val day = dateFormat.format(date)
        val d = java.util.Calendar.getInstance().apply { time = date }.get(java.util.Calendar.DAY_OF_MONTH)
        val suffix = if (d in 11..13) "ᵗʰ" else when (d % 10) { 1 -> "ˢᵗ"; 2 -> "ⁿᵈ"; 3 -> "ʳᵈ"; else -> "ᵗʰ" }
        day.replaceFirst(Regex("""\d+\."""), "$d$suffix")
    }
    val versionPrefix = BuildConfig.VERSION_NAME.split(".").take(3).joinToString(".")
    val versionSuffix = BuildConfig.BUILD_HASH.take(7)

    val isDarkTheme = isSystemInDarkTheme()

    Canvas(
        modifier = modifier.fillMaxSize()
    ) {
        val canvasWidth = size.width
        val canvasHeight = size.height

        val diagonal = kotlin.math.sqrt(canvasWidth * canvasWidth + canvasHeight * canvasHeight)

        rotate(degrees = rotationDegrees, pivot = Offset(canvasWidth / 2, canvasHeight / 2)) {
            val colorValue = if (isDarkTheme) 255 else 0
            val paint = android.graphics.Paint().apply {
                color = android.graphics.Color.argb(
                    (alpha * 255).toInt(),
                    colorValue, colorValue, colorValue
                )
                textSize = textSizePx
                isAntiAlias = true
                typeface = android.graphics.Typeface.MONOSPACE
            }

            val lineHeight = paint.fontSpacing
            val smallPaint = android.graphics.Paint(paint).apply {
                textSize = textSizePx * 0.5f
            }
            val prefixWidth = paint.measureText(versionPrefix)
            val suffixWidth = smallPaint.measureText(versionSuffix)
            val suffixBgPaint = android.graphics.Paint().apply {
                color = android.graphics.Color.argb(
                    (alpha * 0.1f * 255).toInt(),
                    colorValue, colorValue, colorValue
                )
                style = android.graphics.Paint.Style.FILL
            }
            val maxTextWidth = maxOf(
                prefixWidth + suffixWidth,
                paint.measureText(timeString)
            )
            val safeHSpacing = maxOf(spacingPx, maxTextWidth * 1.3f)
            val safeVSpacing = maxOf(spacingPx * 0.6f, lineHeight * 2.5f)

            val startX = -diagonal / 2
            val startY = -diagonal / 2 + lineHeight
            val endX = canvasWidth + diagonal / 2
            val endY = canvasHeight + diagonal / 2

            var y = startY
            while (y < endY) {
                var x = startX
                while (x < endX) {
                    drawContext.canvas.nativeCanvas.drawText(versionPrefix, x, y, paint)
                    drawContext.canvas.nativeCanvas.drawRect(
                        x + prefixWidth - suffixWidth * 0.05f,
                        y - lineHeight * 0.45f,
                        x + prefixWidth + suffixWidth * 1.05f,
                        y + lineHeight * 0.1f,
                        suffixBgPaint
                    )
                    drawContext.canvas.nativeCanvas.drawText(versionSuffix, x + prefixWidth, y, smallPaint)
                    drawContext.canvas.nativeCanvas.drawText(timeString, x + prefixWidth * 0.3f, y + lineHeight, paint)
                    x += safeHSpacing
                }
                y += safeVSpacing
            }
        }
    }
}
