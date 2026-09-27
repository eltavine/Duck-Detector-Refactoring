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

import androidx.compose.animation.core.AnimationState
import androidx.compose.animation.core.DecayAnimationSpec
import androidx.compose.animation.core.animate
import androidx.compose.animation.core.animateDecay
import androidx.compose.animation.core.animateTo
import androidx.compose.animation.core.spring
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlin.math.abs

internal data class WallVelocityHandoff(val velocity: Offset, val uptimeMillis: Long) {
    // 仅跨越紧接着的抬指事件保留速度，停住手指后不再沿用先前惯性
    fun velocityAtRelease(releaseTimeMillis: Long): Offset? =
        velocity.takeIf { releaseTimeMillis - uptimeMillis in 0L..40L }
}

internal suspend fun settleContributorWall(
    initialOffset: Offset,
    initialVelocity: Offset,
    limit: Offset,
    viewport: Size,
    decay: DecayAnimationSpec<Float>,
    onFrame: (Offset) -> Unit,
) = coroutineScope {
    var current = initialOffset
    // 两个方向独立减速，碰到一条边时仍能沿另一条边滑动
    launch {
        settleAxis(initialOffset.x, initialVelocity.x, limit.x, viewport.width, decay) {
            current = current.copy(x = it)
            onFrame(current)
        }
    }
    launch {
        settleAxis(initialOffset.y, initialVelocity.y, limit.y, viewport.height, decay) {
            current = current.copy(y = it)
            onFrame(current)
        }
    }
}

private suspend fun settleAxis(
    initial: Float,
    velocity: Float,
    bound: Float,
    extent: Float,
    decay: DecayAnimationSpec<Float>,
    onFrame: (Float) -> Unit,
) {
    val rebound = spring<Float>(dampingRatio = 0.85f, stiffness = 220f)
    if (abs(initial) > bound) {
        animate(initial, initial.coerceIn(-bound, bound), animationSpec = rebound) { value, _ -> onFrame(value) }
        return
    }
    if (velocity == 0f || bound == 0f) return
    val motion = AnimationState(initialValue = initial, initialVelocity = velocity)
    motion.animateDecay(decay) {
        onFrame(resistWallAxis(value, bound, extent))
        if (abs(value) > bound) cancelAnimation()
    }
    if (abs(motion.value) > bound) {
        // 沿用碰撞时的速度，让惯性自然过渡到边界回弹
        motion.animateTo(
            targetValue = motion.value.coerceIn(-bound, bound),
            animationSpec = rebound,
            sequentialAnimation = true,
        ) { onFrame(resistWallAxis(value, bound, extent)) }
    }
}
