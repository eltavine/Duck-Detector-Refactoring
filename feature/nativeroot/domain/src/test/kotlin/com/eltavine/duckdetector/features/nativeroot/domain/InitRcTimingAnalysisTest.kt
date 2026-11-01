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
import org.junit.Test

class InitRcTimingAnalysisTest {
    @Test
    fun `a repeated interaction survives independent comm and filename main effects and round drift`() {
        val analysis = observation(List(32) { 50L }).analysis
        assertEquals(InitRcTimingVerdict.REPEATABLE_INTERACTION, analysis.verdict)
        assertEquals(50.0, analysis.medianContrastNanos, 0.001)
        assertEquals(0.0, analysis.madNanos, 0.001)
        assertEquals(32, analysis.positiveRounds)
        assertEquals(List(4) { 50.0 }, analysis.orderMediansNanos)
    }

    @Test
    fun `comm and filename main effects alone do not create an interaction`() {
        val analysis = observation(List(32) { 0L }).analysis
        assertEquals(InitRcTimingVerdict.NO_REPEATABLE_INTERACTION, analysis.verdict)
        assertEquals(0.0, analysis.medianContrastNanos, 0.001)
    }

    @Test
    fun `one affected order or half cannot pass repeatability`() {
        val orderEffect = observation(List(32) { if (it % 4 == 0) 200L else 0L })
        val halfEffect = observation(List(32) { if (it < 16) 200L else 0L })
        for (sample in listOf(orderEffect, halfEffect)) {
            assertEquals(InitRcTimingVerdict.NO_REPEATABLE_INTERACTION, sample.analysis.verdict)
        }
    }

    @Test
    fun `positive count boundary and each order are enforced independently`() {
        val boundary = List(32) { if (it < 4) -50L else 50L }
        assertEquals(InitRcTimingVerdict.REPEATABLE_INTERACTION, observation(boundary).analysis.verdict)
        assertEquals(InitRcTimingVerdict.NO_REPEATABLE_INTERACTION,
            observation(boundary.toMutableList().apply { this[4] = -50 }).analysis.verdict)
        // 28 positive rounds, but all four negative rounds have the same order.
        assertEquals(InitRcTimingVerdict.NO_REPEATABLE_INTERACTION,
            observation(List(32) { if (it < 16 && it % 4 == 0) -50L else 50L }).analysis.verdict)
    }

    @Test
    fun `dispersion and negative effects stay descriptive without a positive verdict`() {
        for (effects in listOf(List(32) { -50L }, List(32) { it.toLong() + 1 })) {
            assertEquals(InitRcTimingVerdict.NO_REPEATABLE_INTERACTION, observation(effects).analysis.verdict)
        }
    }

    @Test
    fun `partial and invalid successful observations remain inconclusive`() {
        val valid = observation(List(32) { 50L })
        for (sample in listOf(
            valid.copy(rounds = valid.rounds.drop(1)), valid.copy(cpu = -1), valid.copy(iterations = 1),
            valid.copy(rounds = valid.rounds.toMutableList().apply { this[0] = this[0].copy(initTargetNanos = 0) }),
            valid.copy(rounds = valid.rounds.toMutableList().apply { this[0] = this[0].copy(initTargetNanos = Long.MAX_VALUE) }),
        )) assertEquals(InitRcTimingVerdict.INCONCLUSIVE, sample.analysis.verdict)
    }

    @Test
    fun `collection or cleanup failure invalidates even a full positive sample`() {
        val valid = observation(List(32) { 50L })
        for (stage in InitRcTimingCollection.entries.filter { it != InitRcTimingCollection.COLLECTED }) {
            assertEquals(InitRcTimingVerdict.NOT_EVALUATED, valid.copy(collection = stage).analysis.verdict)
        }
        for (sample in listOf(valid.copy(cleanupCompleted = false), valid.copy(errorNumber = 1),
            valid.copy(cleanupErrorNumber = 1))) {
            assertEquals(InitRcTimingVerdict.NOT_EVALUATED, sample.analysis.verdict)
        }
    }

    @Test
    fun `individually valid batches cannot exceed the whole experiment budget`() {
        val fullSecond = observation(List(32) { 50L }).copy(
            rounds = List(32) { InitRcTimingRound(7_812_500, 7_812_500, 7_812_500, 7_812_500) },
        )
        assertEquals(InitRcTimingVerdict.INCONCLUSIVE, fullSecond.analysis.verdict)
        assertEquals(InitRcTimingVerdict.INCONCLUSIVE, fullSecond.copy(
            rounds = List(32) { InitRcTimingRound(10_000_000, 10_000_000, 10_000_000, 10_000_000) },
        ).analysis.verdict)
    }

    private fun observation(effects: List<Long>) = InitRcTimingObservation(
        collection = InitRcTimingCollection.COLLECTED,
        cpu = 2,
        cleanupCompleted = true,
        rounds = effects.mapIndexed { index, effect ->
            val base = 128_000L + index * 20_000
            InitRcTimingRound(base, base + 40 * 128, base + 80 * 128, base + (120 + effect) * 128)
        },
    )
}
