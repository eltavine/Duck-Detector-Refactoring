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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContributorWallGeometryTest {
    @Test
    fun twentyNineContributorsFormBalancedPairsAroundTheFirstContributor() {
        val centers = contributorWallGeometry(29, avatarSize = 56f, gap = 6f).centers
        assertEquals(Offset.Zero, centers.first())
        centers.forEach { position ->
            assertTrue("missing opposite of $position", centers.any { (it + position).getDistance() < 0.001f })
        }
    }

    @Test
    fun allContributorsHaveDistinctNonOverlappingHoneycombPositions() {
        for (count in listOf(0, 1, 7, 29, 100)) {
            val geometry = contributorWallGeometry(count, avatarSize = 48f, gap = 8f)
            assertEquals(count, geometry.centers.size)
            for (i in geometry.centers.indices) {
                for (j in 0 until i) {
                    assertTrue((geometry.centers[i] - geometry.centers[j]).getDistance() >= 55.99f)
                }
            }
            val viewport = Size(280f, 320f)
            val scale = geometry.fitScale(viewport)
            assertTrue(geometry.contentSize.width * scale <= viewport.width + 0.001f)
            assertTrue(geometry.contentSize.height * scale <= viewport.height + 0.001f)
            assertEquals(0f, geometry.panLimit(viewport, scale).getDistance(), 0.001f)
        }
    }

    @Test
    fun zoomKeepsTheContentUnderTheFingersWhileApplyingPan() {
        val moved = zoomAround(
            offset = Offset(10f, 20f),
            centroid = Offset(50f, 80f),
            pan = Offset(7f, -9f),
            ratio = 2f,
        )
        assertEquals(Offset(-23f, -49f), moved)
        assertEquals(Offset(57f, 71f), Offset(40f, 60f) * 2f + moved)
    }

    @Test
    fun panStopsAtEachEdgeAndCentersContentSmallerThanViewport() {
        val geometry = ContributorWallGeometry(emptyList(), Size(600f, 200f))
        val limit = geometry.panLimit(Size(300f, 300f), 1f)
        assertEquals(Offset(150f, 0f), limit)
        assertEquals(Offset(150f, 0f), constrainWallOffset(Offset(500f, -100f), limit))
        assertEquals(Offset(-150f, 0f), constrainWallOffset(Offset(-500f, 100f), limit))
    }

    @Test
    fun draggingBeyondBoundsHasFiniteElasticTravelAndSettlesToTheEdge() {
        val limit = Offset(150f, 80f)
        val viewport = Size(300f, 400f)
        val far = resistWallOffset(Offset(100_000f, -100_000f), limit, viewport)
        assertTrue(far.x > 150f && far.x < 204f)
        assertTrue(far.y < -80f && far.y > -152f)
        assertEquals(Offset(150f, -80f), constrainWallOffset(far, limit))
        assertEquals(Offset(30f, -40f), resistWallOffset(Offset(30f, -40f), limit, viewport))
    }

    @Test
    fun interruptingOverscrollResumesWithoutDampingTheSameOffsetAgain() {
        val limit = Offset(100f, 80f)
        val viewport = Size(300f, 400f)
        for (displayed in listOf(Offset(140f, 120f), Offset(-140f, -120f), Offset(30f, -40f))) {
            val raw = unresistWallOffset(displayed, limit, viewport)
            val resumed = resistWallOffset(raw, limit, viewport)
            assertEquals(displayed.x, resumed.x, 0.001f)
            assertEquals(displayed.y, resumed.y, 0.001f)
        }
    }

    @Test
    fun bubblesShrinkAndPackGraduallyTowardsEveryEdge() {
        val viewport = Size(300f, 300f)
        assertEquals(WallBubbleTransform(Offset.Zero, 1f), wallBubbleTransform(Offset.Zero, viewport))
        for (direction in listOf(Offset(1f, 0f), Offset(-1f, 0f), Offset(0f, 1f), Offset(0f, -1f))) {
            var previousScale = 1f
            var previousDistance = 0f
            for (distance in 0..300) {
                val bubble = wallBubbleTransform(direction * distance.toFloat(), viewport)
                assertTrue(bubble.scale <= previousScale)
                assertTrue(bubble.scale >= 0.35f)
                assertTrue(bubble.position.getDistance() >= previousDistance)
                previousScale = bubble.scale
                previousDistance = bubble.position.getDistance()
            }
            assertTrue(wallBubbleTransform(direction * 150f, viewport).scale < 0.5f)
        }
    }
}
