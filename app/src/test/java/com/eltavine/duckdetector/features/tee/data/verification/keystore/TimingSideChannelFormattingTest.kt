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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TimingSideChannelFormattingTest {

    @Test
    fun `partial failure reason appends warning to detail`() {
        val detail = buildTimingSideChannelDetail(
            source = "keystore2_security_level_proxy",
            timerSource = "arm64_cntvct",
            affinity = "bound_cpu0",
            avgAttestedMillis = 0.310,
            avgNonAttestedMillis = null,
            diffMillis = null,
            suspicious = false,
            sampleCount = 1000,
            warmupCount = 5,
            measurementDetail = "service.getKeyEntry timing via private binder proxy",
            timerFallbackReason = null,
            partialFailureReason = "non-attested path unavailable",
        )

        assertTrue(detail.contains("service.getKeyEntry timing via private binder proxy"))
        assertTrue(detail.contains("partialFailure=non-attested path unavailable"))
        assertTrue(detail.contains("timer=arm64_cntvct"))
    }

    @Test
    fun `paired diff helper keeps same-loop pairing semantics`() {
        val paired = pairedDiffSeries(
            attestedSamples = listOf(0.62, 0.61, 0.60),
            nonAttestedSamples = listOf(0.30, 0.31, 0.29),
        )

        assertEquals(listOf(0.32, 0.30, 0.31), paired)
    }

    @Test
    fun `paired diff helper truncates to completed pairs only`() {
        val paired = pairedDiffSeries(
            attestedSamples = listOf(0.62, 0.61, 0.60),
            nonAttestedSamples = listOf(0.30, 0.31),
        )

        assertEquals(listOf(0.32, 0.30), paired)
    }

    @Test
    fun `detail includes filtered bad sample count when post filtering removes outliers`() {
        val detail = buildTimingSideChannelDetail(
            source = "keystore2_security_level_proxy",
            timerSource = "arm64_cntvct",
            affinity = "bound_cpu0",
            avgAttestedMillis = 0.612,
            avgNonAttestedMillis = 0.300,
            diffMillis = 0.312,
            suspicious = true,
            sampleCount = 18,
            warmupCount = 5,
            measurementDetail = "service.getKeyEntry timing via private binder proxy",
            timerFallbackReason = null,
            partialFailureReason = "filteredBadSamples=2/20",
        )

        assertTrue(detail.contains("filteredBadSamples=2/20"))
        assertTrue(detail.contains("samples=18"))
    }

    @Test
    fun `stable timer helper treats register timer as hard requirement when requested`() {
        val stable = stableTimerReadNs(
            preferRegisterTimer = true,
            registerTimerSource = { 42L },
            monotonicSource = { 7L },
        )

        assertEquals(42L, stable)
    }

    @Test(expected = IllegalStateException::class)
    fun `stable timer helper fails instead of silently falling back when register timer read fails`() {
        stableTimerReadNs(
            preferRegisterTimer = true,
            registerTimerSource = { null },
            monotonicSource = { 7L },
        )
    }

    @Test
    fun `stable timer helper uses monotonic only when register timer not requested`() {
        val stable = stableTimerReadNs(
            preferRegisterTimer = false,
            registerTimerSource = { null },
            monotonicSource = { 7L },
        )

        assertEquals(7L, stable)
    }

    @Test
    fun `timing side-channel copy payload prefers warmup stacks`() {
        val warmup = listOf(
            CapturedThrowableRecord(
                phase = "warmup.attested[0]",
                summary = "ServiceSpecificException(code 7)",
                stackTrace = "stack-a",
                fingerprint = "a",
                occurrenceCount = 2,
            ),
        )
        val gateway = listOf(
            CapturedThrowableRecord(
                phase = "securityLevel.generateKey",
                summary = "RemoteException",
                stackTrace = "stack-b",
                fingerprint = "b",
            ),
        )

        val payload = selectTimingSideChannelCopyPayload(warmup, gateway)

        assertTrue(payload.contains("phase=warmup.attested[0]"))
        assertTrue(payload.contains("occurrences=2"))
        assertFalse(payload.contains("securityLevel.generateKey"))
    }

    @Test
    fun `timing side-channel copy payload falls back to gateway stacks when warmup is empty`() {
        val gateway = listOf(
            CapturedThrowableRecord(
                phase = "service.getSecurityLevel",
                summary = "IllegalStateException: unavailable",
                stackTrace = "stack-c",
                fingerprint = "c",
            ),
        )

        val payload = selectTimingSideChannelCopyPayload(emptyList(), gateway)

        assertTrue(payload.contains("phase=service.getSecurityLevel"))
    }

    @Test
    fun `timing side-channel copy payload becomes null when no stacks exist`() {
        assertEquals("null", selectTimingSideChannelCopyPayload(emptyList(), emptyList()))
    }
}
