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

package com.eltavine.duckdetector.features.deviceinfo.data

import android.graphics.Bitmap
import android.graphics.Color
import androidx.annotation.ColorInt
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.util.EnumMap

object DeviceInfoQrGenerator {

    private const val DEFAULT_QR_SIZE = 512
    private const val MARGIN = 1

    /** 16-colour palette — all dark enough for reliable scanning. */
    @ColorInt
    private val PALETTE_16 = intArrayOf(
        Color.rgb(0xC6, 0x28, 0x28), // red 800
        Color.rgb(0xAD, 0x14, 0x57), // pink 800
        Color.rgb(0x6A, 0x1B, 0x9A), // purple 800
        Color.rgb(0x28, 0x35, 0x93), // indigo 800
        Color.rgb(0x15, 0x65, 0xC0), // blue 800
        Color.rgb(0x00, 0x83, 0x8F), // teal 800
        Color.rgb(0x00, 0x69, 0x5C), // teal 900
        Color.rgb(0x2E, 0x7D, 0x32), // green 800
        Color.rgb(0x55, 0x8B, 0x2F), // light-green 800
        Color.rgb(0xEF, 0x6C, 0x00), // orange 800
        Color.rgb(0xE6, 0x51, 0x00), // orange 900
        Color.rgb(0xBF, 0x36, 0x0C), // deep-orange 900
        Color.rgb(0x4E, 0x34, 0x2E), // brown 800
        Color.rgb(0x37, 0x47, 0x4F), // blue-grey 800
        Color.rgb(0x42, 0x42, 0x42), // grey 800
        Color.rgb(0x21, 0x21, 0x21), // grey 900
    )

    @ColorInt
    private val BACKGROUND_COLOR = Color.WHITE

    /**
     * Generates a 16-colour tiled QR code.
     *
     * The QR code area (excluding quiet zone) is divided into a 4×4 grid.
     * Each cell uses one discrete colour from [PALETTE_16], giving the code
     * a distinctive high-density aesthetic while keeping every dark module
     * well below the scanner's luminance threshold.
     *
     * *Note: standard QR is binary (dark/light). The 16 colours are visual
     * only — the per-module data density is unchanged.*
     */
    fun generate(
        content: String,
        sizePx: Int = DEFAULT_QR_SIZE,
    ): Bitmap? {
        val hints: MutableMap<EncodeHintType, Any> = EnumMap(EncodeHintType::class.java)
        hints[EncodeHintType.ERROR_CORRECTION] = ErrorCorrectionLevel.M
        hints[EncodeHintType.MARGIN] = MARGIN
        hints[EncodeHintType.CHARACTER_SET] = "UTF-8"

        val bitMatrix = runCatching {
            QRCodeWriter().encode(
                content,
                BarcodeFormat.QR_CODE,
                sizePx,
                sizePx,
                hints,
            )
        }.getOrNull() ?: return null

        val width = bitMatrix.width
        val height = bitMatrix.height
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

        // 4×4 colour grid overlay
        val cols = 4
        val rows = 4
        val cellW = width.toFloat() / cols
        val cellH = height.toFloat() / rows

        for (x in 0 until width) {
            val cellX = (x.toFloat() / cellW).toInt().coerceIn(0, cols - 1)
            for (y in 0 until height) {
                if (bitMatrix[x, y]) {
                    val cellY = (y.toFloat() / cellH).toInt().coerceIn(0, rows - 1)
                    val colorIndex = (cellY * cols + cellX) % PALETTE_16.size
                    bitmap.setPixel(x, y, PALETTE_16[colorIndex])
                } else {
                    bitmap.setPixel(x, y, BACKGROUND_COLOR)
                }
            }
        }

        return bitmap
    }
}
