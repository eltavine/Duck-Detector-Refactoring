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
import android.graphics.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.unit.IntSize
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import java.util.zip.CRC32
import kotlin.math.abs

/**
 * Invisible spread-spectrum digital watermark (JPEG & PNG compatible).
 *
 * Adds +15 to the blue channel of non-overlapping 8x8 pixel blocks.
 * The 8x8 grid aligns with JPEG DCT blocks so the modification
 * survives as a DC offset through lossy compression.
 *
 * ### Usage (Modifier extension -- recommended)
 * ```kotlin
 * Box(Modifier.fillMaxSize().digitalWatermark(deviceInfoCard)) {
 *     // your UI content
 * }
 * ```
 *
 * Uses [drawWithContent] to draw AFTER children on the same canvas
 * layer.  [android.graphics.BlendMode.PLUS] adds the watermark to
 * the actual UI pixels -- critical for additive blend to work across
 * Compose render layers.
 */

/** Applies the digital watermark on top of content drawn by this modifier. */
fun Modifier.digitalWatermark(
    deviceInfoCard: DeviceInfoCardModel,
): Modifier {
    return composed {
        var containerSize by mutableStateOf(IntSize.Zero)

        val watermarkBitmap: Bitmap? = remember(containerSize, deviceInfoCard) {
            if (containerSize.width < BLOCK_SIZE * 2 ||
                containerSize.height < BLOCK_SIZE * 2
            ) return@remember null
            buildWatermarkBitmap(
                containerSize.width, containerSize.height, deviceInfoCard,
            )
        }

        this
            .onSizeChanged { containerSize = it }
            .drawWithContent {
                drawContent()  // children first (the actual UI)
                if (watermarkBitmap != null) {
                    val paint = android.graphics.Paint().apply {
                        blendMode = android.graphics.BlendMode.PLUS
                    }
                    drawContext.canvas.nativeCanvas.drawBitmap(
                        watermarkBitmap, 0f, 0f, paint,
                    )
                }
            }
    }
}

/** Writes the digital watermark directly into an exported bitmap. */
fun embedDigitalWatermark(
    bitmap: Bitmap,
    deviceInfoCard: DeviceInfoCardModel,
) {
    if (bitmap.width < BLOCK_SIZE * 2 || bitmap.height < BLOCK_SIZE * 2) {
        return
    }
    val watermarkBitmap = buildWatermarkBitmap(bitmap.width, bitmap.height, deviceInfoCard)
    try {
        val canvas = Canvas(bitmap)
        val paint = android.graphics.Paint().apply {
            blendMode = android.graphics.BlendMode.PLUS
        }
        canvas.drawBitmap(watermarkBitmap, 0f, 0f, paint)
    } finally {
        watermarkBitmap.recycle()
    }
}

/**
 * Legacy composable wrapper.
 *
 * Prefer [Modifier.digitalWatermark] for new code.
 * Wraps [content] in a [Box] with the watermark modifier applied.
 */
@Composable
fun DigitalWatermark(
    deviceInfoCard: DeviceInfoCardModel,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit = {},
) {
    Box(modifier = modifier.fillMaxSize().digitalWatermark(deviceInfoCard)) {
        content()
    }
}

// ── Constants ─────────────────────────────────────────────────────

private const val PRNG_SEED = 0x4B1D57ADL
private const val SPREAD_FACTOR = 32
private const val MAX_SAMPLES_PER_BIT = 8
private const val BLOCK_SIZE = 8
private const val WATERMARK_DELTA = 15
private const val WATERMARK_DOT = WATERMARK_DELTA
private const val MAX_PLACEMENT_RETRIES = 500

// ── Bitmap generation ─────────────────────────────────────────────

private fun buildWatermarkBitmap(
    w: Int, h: Int, card: DeviceInfoCardModel,
): Bitmap {
    val payload = encodeCompactPayload(card)
    val bits = spreadBits(payload, SPREAD_FACTOR)

    val cellsW = w / BLOCK_SIZE
    val cellsH = h / BLOCK_SIZE
    val used = BooleanArray(cellsW * cellsH)

    val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
    val rng = SplitMix64(PRNG_SEED)

    for (bitIdx in bits.indices) {
        for (s in 0 until MAX_SAMPLES_PER_BIT) {
            for (attempt in 0 until MAX_PLACEMENT_RETRIES) {
                val cx = abs(rng.next().toInt()) % cellsW
                val cy = abs(rng.next().toInt()) % cellsH
                val cellIdx = cy * cellsW + cx
                if (!used[cellIdx]) {
                    used[cellIdx] = true
                    if (bits[bitIdx]) writeBlock(bmp, cx, cy)
                    break
                }
            }
        }
    }
    return bmp
}

private fun writeBlock(bmp: Bitmap, cx: Int, cy: Int) {
    val x0 = cx * BLOCK_SIZE
    val y0 = cy * BLOCK_SIZE
    val x1 = minOf(x0 + BLOCK_SIZE, bmp.width)
    val y1 = minOf(y0 + BLOCK_SIZE, bmp.height)
    for (px in x0 until x1) {
        for (py in y0 until y1) {
            bmp.setPixel(px, py, WATERMARK_DOT)
        }
    }
}

// ── Compact payload (14 bytes) ────────────────────────────────────

private fun encodeCompactPayload(card: DeviceInfoCardModel): ByteArray {
    val map = mutableMapOf<String, String>()
    card.sections.forEach { s -> s.rows.forEach { r -> map[r.label] = r.value } }

    val brand = map["Brand"] ?: "Unknown"
    val model = map["Model"] ?: "Unknown"
    val sdk = (map["SDK"] ?: "0").filter { it.isDigit() }.toIntOrNull() ?: 0
    val fingerprint = map["Fingerprint"] ?: "Unknown"
    val soc = map["SOC Model"] ?: "Unknown"

    val brandByte = encodeBrand(brand)
    val modelHash = crc16(model)
    val fpHash = CRC32()
        .apply { update(fingerprint.toByteArray(Charsets.UTF_8)) }
        .value.toInt()
    val socHash = crc16(soc)

    val fields = ByteArray(10)
    fields[0] = brandByte
    fields[1] = (modelHash shr 8).toByte()
    fields[2] = modelHash.toByte()
    fields[3] = sdk.coerceIn(0, 255).toByte()
    fields[4] = (fpHash shr 24).toByte()
    fields[5] = (fpHash shr 16).toByte()
    fields[6] = (fpHash shr 8).toByte()
    fields[7] = fpHash.toByte()
    fields[8] = (socHash shr 8).toByte()
    fields[9] = socHash.toByte()

    val crc = CRC32().apply { update(fields) }.value.toInt()
    val payload = ByteArray(4 + fields.size)
    payload[0] = (crc shr 24).toByte()
    payload[1] = (crc shr 16).toByte()
    payload[2] = (crc shr 8).toByte()
    payload[3] = crc.toByte()
    fields.copyInto(payload, 4)
    return payload
}

private fun encodeBrand(name: String): Byte = when {
    name.contains("Samsung", ignoreCase = true) -> 1
    name.contains("OnePlus", ignoreCase = true) -> 2
    name.contains("Xiaomi", ignoreCase = true) -> 3
    name.contains("Google", ignoreCase = true) -> 4
    name.contains("OPPO", ignoreCase = true) -> 5
    name.contains("vivo", ignoreCase = true) -> 6
    name.contains("realme", ignoreCase = true) -> 7
    name.contains("Motorola", ignoreCase = true) -> 8
    name.contains("Nothing", ignoreCase = true) -> 9
    name.contains("ASUS", ignoreCase = true) -> 10
    name.contains("Sony", ignoreCase = true) -> 11
    name.contains("Huawei", ignoreCase = true) -> 12
    name.contains("Honor", ignoreCase = true) -> 13
    else -> 0
}

private fun crc16(text: String): Int {
    val crc = CRC32()
        .apply { update(text.toByteArray(Charsets.UTF_8)) }
        .value.toInt()
    return (crc shr 16) and 0xFFFF
}

// ── Bit spreading ─────────────────────────────────────────────────

private fun spreadBits(payload: ByteArray, factor: Int): BooleanArray {
    val raw = BooleanArray(payload.size * 8) { i ->
        val b = payload[i / 8].toInt() and 0xFF
        ((b shr (7 - (i % 8))) and 1) == 1
    }
    val spread = BooleanArray(raw.size * factor)
    for (i in raw.indices) {
        val v = raw[i]
        val base = i * factor
        for (r in 0 until factor) spread[base + r] = v
    }
    return spread
}

// ── PRNG ──────────────────────────────────────────────────────────

private class SplitMix64(seed: Long) {
    private var state: ULong = seed.toULong()
    fun next(): Long {
        state += 0x9E3779B97F4A7C15uL
        var z = state
        z = (z xor (z shr 30)) * 0xBF58476D1CE4E5B9uL
        z = (z xor (z shr 27)) * 0x94D049BB133111EBuL
        return (z xor (z shr 31)).toLong()
    }
}
