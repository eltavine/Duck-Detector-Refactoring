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

package com.eltavine.duckdetector.features.nativeroot.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuTimingAnalysisTest {
    private val count = KernelSuTimingProfile.SAMPLE_COUNT
    private fun vectors(first: ULong = 10uL, target: ULong = 20uL, second: ULong = first) =
        listOf(first, target, second, first, first, first).map { List(count) { _ -> it } }

    @Test fun `both classifiers must match`() {
        val analysis = KernelSuTimingClassifier.summarize(vectors())
        assertTrue(analysis.distance.matched)
        assertTrue(analysis.similarity.matched)
        assertTrue(analysis.matched)
        assertFalse(analysis.copy(distance = KernelSuTimingDistance(count, count, count, 0)).matched)
        assertFalse(analysis.copy(similarity = analysis.similarity.copy(targetSimilarity = 1.0)).matched)
    }

    @Test fun `equal and midpoint samples select the zero feature`() {
        val equal = KernelSuTimingClassifier.summarize(vectors(10uL, 10uL))
        assertEquals(KernelSuTimingDistance(count, count, count, 0), equal.distance)
        assertFalse(equal.matched)
        val midpoint = KernelSuTimingClassifier.summarize(vectors(0uL, 10uL, 20uL))
        assertEquals(count, midpoint.distance.targetZeros)
        assertEquals(0, midpoint.distance.jointTargetHigh)
    }

    @Test fun `unsigned ordering and distances preserve the full counter range`() {
        val result = KernelSuTimingClassifier.summarize(vectors(1uL, ULong.MAX_VALUE))
        assertEquals(0, result.distance.targetZeros)
        assertEquals(count, result.distance.jointTargetHigh)
    }

    @Test fun `distance boundaries are inclusive and filter whole joint counts`() {
        assertTrue(KernelSuTimingDistance(8000, 5100, 7200, 1800).matched)
        assertFalse(KernelSuTimingDistance(8001, 5100, 7200, 1800).matched)
        assertFalse(KernelSuTimingDistance(8000, 5101, 7200, 1800).matched)
        assertFalse(KernelSuTimingDistance(8000, 5100, 7200, 1799).matched)
        for (joint in listOf(49, 50, 51)) {
            assertEquals(if (joint < 50) 0 else joint,
                KernelSuTimingDistance(8000, 5100, 7200, joint).filteredJointCount)
        }
    }

    @Test fun `cosine and mean filters use strict frequency thresholds`() {
        fun histogram(frequency: Int) = (0 until count / frequency).associate {
            it.toULong() to frequency
        }
        val sparse = histogram(100)
        val analysis = KernelSuTimingClassifier.analyze(List(6) { sparse },
            KernelSuTimingDistance(count, count, count, 0))
        assertTrue(analysis.similarity.referenceSimilarity.isNaN())
        assertFalse(analysis.valid)
        assertEquals(0, analysis.support.first().firstMass)
        assertTrue(analysis.similarity.referenceMean.isNaN())
        assertFalse(analysis.matched)
        val medium = histogram(500)
        val mediumResult = KernelSuTimingClassifier.analyze(List(6) { medium }, analysis.distance)
        assertTrue(mediumResult.similarity.referenceSimilarity.isNaN())
        assertFalse(mediumResult.valid)
        assertFalse(mediumResult.similarity.referenceMean.isNaN())
    }

    @Test fun `cross control compares the second reference with the first control`() {
        val histograms = listOf(10uL, 20uL, 10uL, 30uL, 30uL, 30uL)
            .map { mapOf(it to count) }
        val result = KernelSuTimingClassifier.analyze(histograms,
            KernelSuTimingDistance(count, 0, count, count))
        assertEquals(0.0, result.similarity.controlSimilarity, 0.0)
        assertEquals(1.0, result.similarity.firstControlSimilarity, 0.0)
        assertFalse(result.matched)
    }

    @Test fun `all similarity thresholds include equality but NaN never matches`() {
        val boundary = KernelSuTimingSimilarity(0.98, 0.94, 0.99, 0.99, 0.99, 10.0, 11.0)
        assertTrue(boundary.matched)
        assertFalse(boundary.copy(referenceSimilarity = Math.nextDown(0.98)).matched)
        assertFalse(boundary.copy(targetSimilarity = Math.nextUp(0.94)).matched)
        assertFalse(boundary.copy(controlSimilarity = Math.nextDown(0.99)).matched)
        assertFalse(boundary.copy(firstControlSimilarity = Math.nextDown(0.99)).matched)
        assertFalse(boundary.copy(secondControlSimilarity = Math.nextDown(0.99)).matched)
        assertFalse(boundary.copy(referenceMean = Double.NaN).matched)
        assertFalse(boundary.copy(targetMean = 10.0).matched)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `malformed histogram cannot become an absent observation`() {
        KernelSuTimingClassifier.analyze(List(6) { mapOf(1uL to -1) },
            KernelSuTimingDistance(count, 0, count, count))
    }

    @Test fun `configured boundary matrix covers joint features midpoints scores and conjunction`() {
        var checked = 0
        for (pattern in 0..7) for (frequency in listOf(45, 50, 55)) {
            val samples = (0..5).map { position -> List(count) { index ->
                if (position < 3 && index < frequency && pattern and (1 shl (2 - position)) != 0) 20uL else 0uL
            } }
            val analysis = KernelSuTimingClassifier.summarize(samples)
            assertEquals(if (pattern == 2 && frequency >= 50) frequency else 0, analysis.distance.filteredJointCount)
            checked++
        }
        for (value in listOf(0uL, 4uL, 5uL, 6uL, 10uL)) {
            val analysis = KernelSuTimingClassifier.summarize(vectors(0uL, value, 10uL))
            assertEquals(if (value > 5uL) 0 else count, analysis.distance.targetZeros)
            checked++
        }
        assertEquals(count, KernelSuTimingClassifier.summarize(vectors(5uL, 5uL)).distance.targetZeros)
        checked++
        val baseline = KernelSuTimingSimilarity(0.98, 0.94, 0.99, 0.99, 0.99, 1.0, 2.0)
        assertTrue(baseline.matched)
        checked++
        for (index in 0..4) for (nan in listOf(false, true)) {
            val scores = mutableListOf(0.98, 0.94, 0.99, 0.99, 0.99)
            scores[index] = if (nan) Double.NaN else if (index == 1) Math.nextUp(scores[index]) else Math.nextDown(scores[index])
            assertFalse(KernelSuTimingSimilarity(scores[0], scores[1], scores[2], scores[3], scores[4], 1.0, 2.0).matched)
            checked++
        }
        for ((reference, target) in listOf(2.0 to 2.0, 3.0 to 2.0, 1.0 to Double.NaN, Double.NaN to 2.0)) {
            assertFalse(baseline.copy(referenceMean = reference, targetMean = target).matched)
            checked++
        }
        for (distanceMatches in listOf(false, true)) for (similarityMatches in listOf(false, true)) {
            val distance = if (distanceMatches) KernelSuTimingDistance(count, 0, count, count)
                else KernelSuTimingDistance(count, count, count, 0)
            val similarity = if (similarityMatches) baseline else baseline.copy(targetSimilarity = 1.0)
            assertEquals(distanceMatches && similarityMatches, KernelSuTimingAnalysis(distance, similarity, List(6) { KernelSuTimingSupport(1, count, count) }).matched)
            checked++
        }
        assertEquals(49, checked)
    }

    @Test fun `strict bins floor reference averaging and unsigned weighted sums are preserved`() {
        fun histogram(frequency: Int) = (0 until count / frequency).associate { it.toULong() to frequency } +
            if (count % frequency != 0) mapOf(1000uL to count % frequency) else emptyMap()
        val distance = KernelSuTimingDistance(count, count, count, 0)
        val hundred = KernelSuTimingClassifier.analyze(List(6) { histogram(100) }, distance).similarity
        val hundredOne = KernelSuTimingClassifier.analyze(List(6) { histogram(101) }, distance).similarity
        assertTrue(hundred.referenceMean.isNaN())
        assertFalse(hundredOne.referenceMean.isNaN())
        assertTrue(KernelSuTimingClassifier.analyze(List(6) { histogram(500) }, distance).similarity.referenceSimilarity.isNaN())
        assertEquals(1.0, KernelSuTimingClassifier.analyze(List(6) { histogram(501) }, distance).similarity.referenceSimilarity, 1e-15)
        val first = mapOf(1uL to 101, 2uL to 9899)
        val second = mapOf(1uL to 100, 2uL to 9900)
        val floor = KernelSuTimingClassifier.analyze(listOf(first, second, second, first, first, first), distance).similarity
        assertEquals(2.0, floor.referenceMean, 0.0)
        val wrapped = KernelSuTimingClassifier.analyze(List(6) { mapOf(ULong.MAX_VALUE to count) }, distance).similarity
        assertEquals((ULong.MAX_VALUE * count.toULong()).toDouble() / count, wrapped.referenceMean, 0.0)
    }
    @Test fun `retained minority is insufficient even with nonempty finite metrics`() {
        fun histogram(mass: Int) = mapOf(0uL to mass) + (1..(count - mass)).associate { it.toULong() to 1 }
        val distance = KernelSuTimingDistance(count, count, count, 0)
        for (mass in listOf(501, 5000, 5001, count)) {
            val result = KernelSuTimingClassifier.analyze(List(6) { histogram(mass) }, distance)
            assertEquals(mass >= 5001, result.valid)
            assertEquals(mass, result.support.first().firstMass)
            assertEquals(1, result.support.first().retainedBins)
        }
    }

    @Test fun `missing classifier support cannot be a valid negative`() {
        val analysis = KernelSuTimingClassifier.summarize(vectors(10uL, 10uL))
        assertTrue(analysis.valid)
        assertFalse(analysis.copy(support = emptyList()).valid)
        val singleMissing = analysis.support.toMutableList().apply { this[5] = KernelSuTimingSupport(0, 0, 0) }
        assertFalse(analysis.copy(support = singleMissing).valid)
    }

}
