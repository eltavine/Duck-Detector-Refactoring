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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sign
import kotlin.math.sqrt
import kotlin.math.tanh

internal data class ContributorWallGeometry(
    val centers: List<Offset>,
    val contentSize: Size,
) {
    fun fitScale(viewport: Size): Float =
        min(viewport.width / contentSize.width, viewport.height / contentSize.height).coerceAtMost(1f)

    fun panLimit(viewport: Size, scale: Float): Offset = Offset(
        max(0f, (contentSize.width * scale - viewport.width) / 2f),
        max(0f, (contentSize.height * scale - viewport.height) / 2f),
    )
}

internal fun contributorWallGeometry(count: Int, avatarSize: Float, gap: Float): ContributorWallGeometry {
    require(count >= 0 && avatarSize > 0f && gap >= 0f)
    if (count == 0) return ContributorWallGeometry(emptyList(), Size(avatarSize, avatarSize))
    var radius = 0
    while (1 + 3 * radius * (radius + 1) < count) radius++
    val spacing = avatarSize + gap
    val pairs = buildList {
        for (r in -radius..radius) {
            for (q in -radius..radius) {
                if (abs(q + r) <= radius && (r > 0 || r == 0 && q > 0)) {
                    val point = Offset((q + r / 2f) * spacing, r * spacing * sqrt(3f) / 2f)
                    add((q * q + q * r + r * r) to point)
                }
            }
        }
    }.sortedWith(compareBy<Pair<Int, Offset>> { it.first }.thenBy { atan2(it.second.y, it.second.x) })
    // 成对选择外圈位置，避免人数不足一整圈时整面墙偏向一侧
    val centers = (listOf(Offset.Zero) + pairs.flatMap { listOf(it.second, -it.second) }).take(count)
    val minX = centers.minOf { it.x }
    val maxX = centers.maxOf { it.x }
    val minY = centers.minOf { it.y }
    val maxY = centers.maxOf { it.y }
    val center = Offset((minX + maxX) / 2f, (minY + maxY) / 2f)
    return ContributorWallGeometry(
        centers = centers.map { it - center },
        contentSize = Size(maxX - minX + avatarSize, maxY - minY + avatarSize),
    )
}

internal fun zoomAround(offset: Offset, centroid: Offset, pan: Offset, ratio: Float): Offset =
    (offset - centroid) * ratio + centroid + pan

internal fun constrainWallOffset(offset: Offset, limit: Offset): Offset = Offset(
    if (limit.x == 0f) 0f else offset.x.coerceIn(-limit.x, limit.x),
    if (limit.y == 0f) 0f else offset.y.coerceIn(-limit.y, limit.y),
)

internal fun resistWallOffset(offset: Offset, limit: Offset, viewport: Size): Offset {
    return Offset(
        resistWallAxis(offset.x, limit.x, viewport.width),
        resistWallAxis(offset.y, limit.y, viewport.height),
    )
}

internal fun resistWallAxis(value: Float, bound: Float, extent: Float): Float {
    val overflow = abs(value) - bound
    if (overflow <= 0f) return value
    val travel = extent * 0.18f
    return sign(value) * (bound + travel * overflow / (travel + overflow))
}

internal fun unresistWallOffset(offset: Offset, limit: Offset, viewport: Size): Offset {
    fun restore(value: Float, bound: Float, extent: Float): Float {
        val overflow = abs(value) - bound
        if (overflow <= 0f) return value
        val travel = extent * 0.18f
        val visibleOverflow = overflow.coerceAtMost(travel * 0.999f)
        return sign(value) * (bound + travel * visibleOverflow / (travel - visibleOverflow))
    }
    return Offset(
        restore(offset.x, limit.x, viewport.width),
        restore(offset.y, limit.y, viewport.height),
    )
}

internal data class WallBubbleTransform(val position: Offset, val scale: Float)

internal fun wallBubbleTransform(position: Offset, viewport: Size): WallBubbleTransform {
    val distance = max(abs(position.x) / (viewport.width / 2), abs(position.y) / (viewport.height / 2))
    if (distance <= 0.3f) return WallBubbleTransform(position, 1f)
    val edgeDistance = distance - 0.3f
    val curve = tanh(edgeDistance / 0.42f)
    val compressedDistance = 0.3f + 0.35f * edgeDistance + 0.65f * 0.42f * curve
    // 缩放与位置压缩使用同一条曲线，边缘头像缩小时仍保持紧凑间距
    val scale = 0.35f + 0.65f * (1f - curve * curve)
    return WallBubbleTransform(position * (compressedDistance / distance), scale)
}
