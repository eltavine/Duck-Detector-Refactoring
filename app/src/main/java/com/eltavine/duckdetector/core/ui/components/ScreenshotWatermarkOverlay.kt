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
            val now = System.currentTimeMillis()
            currentTimeMillis = now
            val delayMillis = (60_000L - (now % 60_000L)).coerceAtLeast(1_000L)
            delay(delayMillis)
        }
    }

    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }
    val timeLine = remember(currentTimeMillis) {
        dateFormat.format(Date(currentTimeMillis))
    }
    val versionLine = "${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})"

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
            val width1 = paint.measureText(versionLine)
            val width2 = paint.measureText(timeLine)
            val maxTextWidth = maxOf(width1, width2)
            val offset1 = (maxTextWidth - width1) / 2f
            val offset2 = (maxTextWidth - width2) / 2f

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
                    drawContext.canvas.nativeCanvas.drawText(versionLine, x + offset1, y, paint)
                    drawContext.canvas.nativeCanvas.drawText(timeLine, x + offset2, y + lineHeight, paint)
                    x += safeHSpacing
                }
                y += safeVSpacing
            }
        }
    }
}
