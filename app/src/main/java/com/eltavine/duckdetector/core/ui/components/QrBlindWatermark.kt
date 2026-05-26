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

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import androidx.compose.animation.core.InfiniteTransition
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.features.deviceinfo.data.DeviceInfoExportFormatter
import com.eltavine.duckdetector.features.deviceinfo.data.DeviceInfoQrGenerator
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import kotlin.math.cos
import kotlin.math.sin

/**
 * A floating QR-code blind watermark overlay that tiles device-identity QR codes
 * across the entire screen at very low opacity with a slow drifting animation.
 *
 * Replaces traditional text-based blind watermarks with a scannable QR pattern
 * that can be recovered from screenshots to trace leaked images back to a
 * specific device.
 *
 * The QR codes slowly float (drift) with independent per-tile phase offsets so
 * they are never in exactly the same position, making automated removal harder
 * while remaining unobtrusive during normal use.
 *
 * @param deviceInfoCard    Device info model used to generate the QR code payload.
 * @param alpha             Watermark opacity (0..1). Default 0.05 — nearly invisible.
 * @param qrSizeDp          Size of each QR tile in dp. Default 96.
 * @param spacingDp         Gap between QR tiles in dp. Default 72.
 * @param floatAmplitudeDp  Maximum pixel drift amplitude in dp. Default 18.
 * @param floatPeriodMs     Full drift cycle duration in ms. Default 25_000.
 * @param modifier          Standard Compose modifier.
 */
@Composable
fun QrBlindWatermark(
    deviceInfoCard: DeviceInfoCardModel,
    alpha: Float = 0.05f,
    qrSizeDp: Float = 96f,
    spacingDp: Float = 72f,
    floatAmplitudeDp: Float = 18f,
    floatPeriodMs: Int = 25_000,
    modifier: Modifier = Modifier,
) {
    val density = LocalDensity.current
    val qrSizePx = with(density) { qrSizeDp.dp.toPx() }
    val spacingPx = with(density) { spacingDp.dp.toPx() }
    val amplitudePx = with(density) { floatAmplitudeDp.dp.toPx() }
    val cellSizePx = qrSizePx + spacingPx

    // Generate a small QR bitmap once (solid black, low-res)
    val qrBitmap: Bitmap? = remember(deviceInfoCard) {
        val qrText = DeviceInfoExportFormatter.formatUltraCompact(deviceInfoCard)
        DeviceInfoQrGenerator.generate(
            content = qrText,
            sizePx = qrSizePx.toInt().coerceIn(64, 512),
            gradientStart = Color.BLACK,
            gradientEnd = Color.BLACK,
        )
    }

    if (qrBitmap == null) return

    // Floating animation — two independent slow drifts (X and Y)
    val infiniteTransition: InfiniteTransition =
        rememberInfiniteTransition(label = "qrFloat")

    val floatX by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = floatPeriodMs, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "floatX",
    )
    val floatY by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = (floatPeriodMs * 1.37f).toInt(),
                easing = LinearEasing,
            ),
            repeatMode = RepeatMode.Restart,
        ),
        label = "floatY",
    )

    // Reusable paint for drawing translucent QR tiles
    val tilePaint = remember {
        Paint(Paint.ANTI_ALIAS_FLAG or Paint.FILTER_BITMAP_FLAG)
    }

    Canvas(modifier = modifier.fillMaxSize()) {
        val canvasW = size.width
        val canvasH = size.height

        // Number of tiles needed to cover the screen with margin
        val cols = (canvasW / cellSizePx).toInt() + 2
        val rows = (canvasH / cellSizePx).toInt() + 2

        // Phase for floating animation (0…2π)
        val phaseX = floatX * 2f * Math.PI.toFloat()
        val phaseY = floatY * 2f * Math.PI.toFloat()

        tilePaint.alpha = (alpha * 255).toInt().coerceIn(0, 255)

        for (col in 0 until cols) {
            for (row in 0 until rows) {
                // Each tile has a slightly different phase for natural drift
                val tilePhaseShift = col * 0.7f + row * 1.1f
                val offsetX = sin(phaseX + tilePhaseShift) * amplitudePx
                val offsetY = cos(phaseY + tilePhaseShift) * amplitudePx

                val baseX = col * cellSizePx
                val baseY = row * cellSizePx

                val drawX = baseX + offsetX
                val drawY = baseY + offsetY

                // Skip tiles fully outside the viewport (with float margin)
                if (drawX <= -cellSizePx || drawX >= canvasW + cellSizePx ||
                    drawY <= -cellSizePx || drawY >= canvasH + cellSizePx
                ) {
                    continue
                }

                val destRect = RectF(drawX, drawY, drawX + qrSizePx, drawY + qrSizePx)
                drawContext.canvas.nativeCanvas.drawBitmap(
                    qrBitmap, null, destRect, tilePaint,
                )
            }
        }
    }
}
