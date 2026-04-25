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
import androidx.compose.ui.graphics.Color
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
    alpha: Float = 0.08f,
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

    val versionName = BuildConfig.VERSION_NAME
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }
    val timeString = remember(currentTimeMillis) { dateFormat.format(Date(currentTimeMillis)) }
    val watermarkText = "v$versionName | $timeString"

    val isDarkTheme = isSystemInDarkTheme()
    val textColor =
        if (isDarkTheme) Color.White.copy(alpha = alpha) else Color.Black.copy(alpha = alpha)

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

            val startX = -diagonal / 2
            val startY = -diagonal / 2
            val endX = canvasWidth + diagonal / 2
            val endY = canvasHeight + diagonal / 2

            var y = startY
            while (y < endY) {
                var x = startX
                while (x < endX) {
                    drawContext.canvas.nativeCanvas.drawText(
                        watermarkText,
                        x,
                        y,
                        paint
                    )
                    x += spacingPx
                }
                y += spacingPx * 0.6f
            }
        }
    }
}
