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

    // Default brand gradient colours – warm teal → deep indigo
    @ColorInt
    private val DEFAULT_GRADIENT_START = Color.rgb(0x00, 0x96, 0x88) // teal 500
    @ColorInt
    private val DEFAULT_GRADIENT_END = Color.rgb(0x3F, 0x51, 0xB5)   // indigo 500
    @ColorInt
    private val BACKGROUND_COLOR = Color.WHITE

    /**
     * Generate a colourful QR code bitmap from the given text content.
     *
     * The dark ("on") modules are drawn with a horizontal gradient; the
     * light modules remain white so scanners can still read the code
     * reliably.
     *
     * @param content       The text to encode in the QR code.
     * @param sizePx        Output bitmap size in pixels (square). Defaults to 512.
     * @param gradientStart Start colour of the foreground gradient (top-left).
     * @param gradientEnd   End colour of the foreground gradient (bottom-right).
     * @return A colourful QR code bitmap, or null if the content is too large.
     */
    fun generate(
        content: String,
        sizePx: Int = DEFAULT_QR_SIZE,
        @ColorInt gradientStart: Int = DEFAULT_GRADIENT_START,
        @ColorInt gradientEnd: Int = DEFAULT_GRADIENT_END,
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

        val sr = Color.red(gradientStart)
        val sg = Color.green(gradientStart)
        val sb = Color.blue(gradientStart)
        val er = Color.red(gradientEnd)
        val eg = Color.green(gradientEnd)
        val eb = Color.blue(gradientEnd)

        // Pre-compute per-row gradient colours so we only interpolate once per row
        val rowColors = IntArray(height) { y ->
            val ratio = height.takeIf { it > 1 }?.let { y.toFloat() / (it - 1) } ?: 0f
            val r = (sr + (er - sr) * ratio).toInt().coerceIn(0, 255)
            val g = (sg + (eg - sg) * ratio).toInt().coerceIn(0, 255)
            val b = (sb + (eb - sb) * ratio).toInt().coerceIn(0, 255)
            Color.rgb(r, g, b)
        }

        for (x in 0 until width) {
            for (y in 0 until height) {
                bitmap.setPixel(
                    x,
                    y,
                    if (bitMatrix[x, y]) rowColors[y] else BACKGROUND_COLOR,
                )
            }
        }

        return bitmap
    }
}
