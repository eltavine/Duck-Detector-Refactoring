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

import kotlin.math.abs
import kotlin.math.sqrt

object KernelSuTimingProfile {
    const val SAMPLE_COUNT = 10000
    const val JOINT_MINIMUM = 50
    const val COSINE_BIN_MINIMUM = 500
    const val MEAN_BIN_MINIMUM = 100
    const val REQUIRED_ROUNDS = 3
    const val MAXIMUM_CORES = 16
}

data class KernelSuTimingDistance(
    val firstZeros: Int,
    val targetZeros: Int,
    val secondZeros: Int,
    val jointTargetHigh: Int,
) {
    init {
        require(listOf(firstZeros, targetZeros, secondZeros, jointTargetHigh).all {
            it in 0..KernelSuTimingProfile.SAMPLE_COUNT
        })
        require(jointTargetHigh <= minOf(firstZeros, secondZeros))
        require(jointTargetHigh <= KernelSuTimingProfile.SAMPLE_COUNT - targetZeros)
    }

    val referenceZeros: Int get() = (firstZeros + secondZeros) / 2
    val referenceDifference: Int get() = abs(secondZeros - firstZeros)
    val targetDifference: Int get() = abs(referenceZeros - targetZeros)
    val filteredJointCount: Int
        get() = jointTargetHigh.takeIf { it >= KernelSuTimingProfile.JOINT_MINIMUM } ?: 0
    val matched: Boolean
        get() = firstZeros > targetZeros && secondZeros > targetZeros &&
            referenceDifference <= 800 && filteredJointCount >= 1800 &&
            referenceZeros > targetZeros && targetDifference >= 2500
}

data class KernelSuTimingSimilarity(
    val referenceSimilarity: Double,
    val targetSimilarity: Double,
    val controlSimilarity: Double,
    val firstControlSimilarity: Double,
    val secondControlSimilarity: Double,
    val referenceMean: Double,
    val targetMean: Double,
) {
    val matched: Boolean
        get() = targetMean > referenceMean && referenceSimilarity >= 0.98 &&
            targetSimilarity <= 0.94 && controlSimilarity >= 0.99 &&
            firstControlSimilarity >= 0.99 && secondControlSimilarity >= 0.99
}

data class KernelSuTimingAnalysis(
    val distance: KernelSuTimingDistance,
    val similarity: KernelSuTimingSimilarity,
) {
    val matched: Boolean get() = distance.matched && similarity.matched
}

object KernelSuTimingClassifier {
    fun analyze(
        histograms: List<Map<ULong, Int>>,
        distance: KernelSuTimingDistance,
    ): KernelSuTimingAnalysis {
        require(histograms.size == 6)
        histograms.forEach { histogram ->
            require(histogram.size <= KernelSuTimingProfile.SAMPLE_COUNT)
            require(histogram.values.all { it in 1..KernelSuTimingProfile.SAMPLE_COUNT })
            require(histogram.values.sumOf { it.toLong() } == KernelSuTimingProfile.SAMPLE_COUNT.toLong())
        }
        val first = histograms[0]
        val target = histograms[1]
        val second = histograms[2]
        val reference = (first.keys + second.keys).associateWith {
            ((first[it] ?: 0) + (second[it] ?: 0)) / 2
        }
        val meanKeys = (reference.keys + target.keys).filter {
            (reference[it] ?: 0) > KernelSuTimingProfile.MEAN_BIN_MINIMUM ||
                (target[it] ?: 0) > KernelSuTimingProfile.MEAN_BIN_MINIMUM
        }
        return KernelSuTimingAnalysis(distance, KernelSuTimingSimilarity(
            referenceSimilarity = cosine(first, second),
            targetSimilarity = cosine(reference, target),
            controlSimilarity = cosine(second, histograms[3]),
            firstControlSimilarity = cosine(histograms[3], histograms[4]),
            secondControlSimilarity = cosine(histograms[4], histograms[5]),
            referenceMean = mean(reference, meanKeys),
            targetMean = mean(target, meanKeys),
        ))
    }

    fun summarize(vectors: List<List<ULong>>): KernelSuTimingAnalysis {
        require(vectors.size == 6)
        require(vectors.all { it.size == KernelSuTimingProfile.SAMPLE_COUNT })
        val zeros = IntArray(3)
        var jointTargetHigh = 0
        repeat(KernelSuTimingProfile.SAMPLE_COUNT) { index ->
            val values = listOf(vectors[0][index], vectors[1][index], vectors[2][index])
            val minimum = values.min()
            val maximum = values.max()
            val high = values.map { it - minimum > maximum - it }
            high.forEachIndexed { position, value -> if (!value) zeros[position]++ }
            if (!high[0] && high[1] && !high[2]) jointTargetHigh++
        }
        return analyze(vectors.map { it.groupingBy { ticks -> ticks }.eachCount() },
            KernelSuTimingDistance(zeros[0], zeros[1], zeros[2], jointTargetHigh))
    }

    private fun cosine(first: Map<ULong, Int>, second: Map<ULong, Int>): Double {
        var dot = 0.0
        var firstNorm = 0.0
        var secondNorm = 0.0
        (first.keys + second.keys).forEach { key ->
            val firstCount = first[key] ?: 0
            val secondCount = second[key] ?: 0
            if (firstCount > KernelSuTimingProfile.COSINE_BIN_MINIMUM ||
                secondCount > KernelSuTimingProfile.COSINE_BIN_MINIMUM) {
                dot += firstCount.toDouble() * secondCount
                firstNorm += firstCount.toDouble() * firstCount
                secondNorm += secondCount.toDouble() * secondCount
            }
        }
        return dot / maxOf(1.0, sqrt(firstNorm) * sqrt(secondNorm))
    }

    private fun mean(histogram: Map<ULong, Int>, keys: List<ULong>): Double {
        var weighted = 0uL
        var count = 0uL
        keys.forEach { key ->
            val frequency = (histogram[key] ?: 0).toULong()
            weighted += key * frequency
            count += frequency
        }
        return weighted.toDouble() / count.toDouble()
    }
}
