/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

import androidx.compose.animation.rememberSplineBasedDecay
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.calculateCentroid
import androidx.compose.foundation.gestures.calculatePan
import androidx.compose.foundation.gestures.calculateZoom
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.util.VelocityTracker
import androidx.compose.ui.input.pointer.util.addPointerInputChange
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.features.settings.ui.R
import io.github.xiaotong6666.uihelper.chrome.pagerSwipeExclusion
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

private const val MinWallZoom = 0.6f
private const val MaxWallZoom = 3f
private val WallOffsetSaver = listSaver<Offset, Float>(
    save = { listOf(it.x, it.y) },
    restore = { Offset(it[0], it[1]) },
)

@Composable
internal fun ContributorWallCanvas(
    authors: List<AuthorProfile>,
    onSelect: (AuthorProfile) -> Unit,
    modifier: Modifier = Modifier,
) {
    var zoom by rememberSaveable { mutableFloatStateOf(1.5f) }
    var offset by rememberSaveable(stateSaver = WallOffsetSaver) { mutableStateOf(Offset.Zero) }
    var motionJob by remember { mutableStateOf<Job?>(null) }
    val scope = rememberCoroutineScope()
    val decay = rememberSplineBasedDecay<Float>()
    val density = LocalDensity.current
    val avatarSize = 56.dp
    val geometry = remember(authors.size, density) {
        with(density) { contributorWallGeometry(authors.size, avatarSize.toPx(), 6.dp.toPx()) }
    }
    val detailsLabel = stringResource(R.string.author_view_details)

    BoxWithConstraints(modifier.fillMaxWidth()) {
        val canvasHeight = maxWidth.coerceAtMost(380.dp)
        val viewport = with(density) { Size(maxWidth.toPx(), canvasHeight.toPx()) }
        val inset = with(density) { 8.dp.toPx() }
        val available = Size(viewport.width - inset * 2, viewport.height - inset * 2)
        val fitScale = geometry.fitScale(available)
        val center = Offset(viewport.width / 2, viewport.height / 2)

        LaunchedEffect(geometry, viewport) {
            motionJob?.cancel()
            offset = constrainWallOffset(offset, geometry.panLimit(available, fitScale * zoom))
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(canvasHeight)
                .clip(ShapeTokens.CornerLarge)
                .then(pagerSwipeExclusion())
                .wallEdgeFade()
                .pointerInput(geometry, viewport) {
                    val maximumVelocity = 6000.dp.toPx().let { Velocity(it, it) }
                    awaitEachGesture {
                        val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                        val stoppingMotion = motionJob?.isActive == true
                        motionJob?.cancel()
                        if (stoppingMotion) down.consume()
                        val tracker = VelocityTracker()
                        var trackedPosition = Offset.Zero
                        var pointerCount = 1
                        tracker.addPointerInputChange(down)
                        var rawOffset = unresistWallOffset(
                            offset, geometry.panLimit(available, fitScale * zoom), viewport,
                        )
                        var velocityHandoff: WallVelocityHandoff? = null
                        var releaseTimeMillis = down.uptimeMillis
                        var drag = Offset.Zero
                        var ownsGesture = stoppingMotion
                        do {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            val pan = event.calculatePan()
                            val pressedCount = event.changes.count { it.pressed }
                            val previousEventTimeMillis = releaseTimeMillis
                            releaseTimeMillis = event.changes.first().uptimeMillis
                            if (pressedCount > 0 && pressedCount != pointerCount) {
                                velocityHandoff = if (pointerCount > 1 && pressedCount == 1) {
                                    val velocity = tracker.calculateVelocity(maximumVelocity)
                                    WallVelocityHandoff(Offset(velocity.x, velocity.y), previousEventTimeMillis)
                                } else null
                                tracker.resetTracking()
                                trackedPosition = Offset.Zero
                            }
                            if (pressedCount == 1 && pan != Offset.Zero) {
                                velocityHandoff = null
                            }
                            if (pressedCount == 1 || pressedCount == 0 && pointerCount == 1) {
                                val pointer = event.changes.firstOrNull { it.pressed }
                                    ?: event.changes.first { it.previousPressed }
                                tracker.addPointerInputChange(pointer)
                            } else if (pressedCount > 1) {
                                trackedPosition += pan
                                tracker.addPosition(event.changes.first().uptimeMillis, trackedPosition)
                            }
                            pointerCount = pressedCount
                            drag += pan
                            if (pressedCount >= 2 ||
                                drag.getDistance() > viewConfiguration.touchSlop
                            ) {
                                ownsGesture = true
                            }
                            if (ownsGesture) {
                                val nextZoom = (zoom * event.calculateZoom()).coerceIn(MinWallZoom, MaxWallZoom)
                                val centroid = event.calculateCentroid(useCurrent = false)
                                if (centroid != Offset.Unspecified) {
                                    rawOffset = zoomAround(rawOffset, centroid - center, pan, nextZoom / zoom)
                                }
                                zoom = nextZoom
                                offset = resistWallOffset(
                                    rawOffset,
                                    geometry.panLimit(available, fitScale * zoom),
                                    viewport,
                                )
                                event.changes.forEach { it.consume() }
                            }
                        } while (event.changes.any { it.pressed })
                        if (ownsGesture) {
                            val velocity = tracker.calculateVelocity(maximumVelocity)
                            val releasedVelocity = velocityHandoff?.velocityAtRelease(releaseTimeMillis)
                                ?: Offset(velocity.x, velocity.y)
                            val initialVelocity = releasedVelocity.let {
                                if (it.getDistance() < 50.dp.toPx()) Offset.Zero else it
                            }
                            motionJob = scope.launch {
                                settleContributorWall(
                                    initialOffset = offset,
                                    initialVelocity = initialVelocity,
                                    limit = geometry.panLimit(available, fitScale * zoom),
                                    viewport = viewport,
                                    decay = decay,
                                ) { offset = it }
                            }
                        }
                    }
                },
            contentAlignment = Alignment.Center,
        ) {
            authors.forEachIndexed { index, profile ->
                key(profile.login) {
                    AuthorAvatar(
                        profile = profile,
                        modifier = Modifier
                            .size(avatarSize)
                            .graphicsLayer {
                                val scale = fitScale * zoom
                                val bubble = wallBubbleTransform(geometry.centers[index] * scale + offset, viewport)
                                scaleX = scale * bubble.scale
                                scaleY = scaleX
                                translationX = bubble.position.x
                                translationY = bubble.position.y
                            }
                            .clip(CircleShape)
                            .clickable(
                                role = Role.Button,
                                onClickLabel = detailsLabel,
                                onClick = { onSelect(profile) },
                            )
                            .semantics { contentDescription = profile.name },
                    )
                }
            }
        }
    }
}
