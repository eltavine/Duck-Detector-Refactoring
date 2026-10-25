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

package com.eltavine.duckdetector.features.nativeroot.data.service

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingAnalysis
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCollection
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreAttempt
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCoreStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingDistance
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingObservation
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflight
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingPreflightStatus
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSimilarity
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCpuSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSupport
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingSyscallSummary
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingWindowEvidence
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

internal object KernelSuTimingPayloadCodec {
    // Private same-install carrier protocol; older summaries lack required
    // coverage/outcome/support evidence and are intentionally rejected.
    private const val PAYLOAD_VERSION = 2
    private const val MAX_BYTES = 196608
    private const val MAX_DETAIL_LENGTH = 160

    fun encode(value: KernelSuTimingObservation): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { output ->
            output.writeInt(PAYLOAD_VERSION)
            output.writeInt(value.collection.ordinal)
            output.snapshot(value.initialCpus)
            output.writeBoolean(value.finalCpus != null)
            value.finalCpus?.let { output.snapshot(it) }
            output.writeBoolean(value.cleanupCompleted)
            output.detail(value.detail)
            output.writeInt(value.attempts.size)
            value.attempts.forEach { core ->
                output.writeInt(core.requestedCpu)
                output.writeInt(core.actualCpu ?: -1)
                output.writeInt(core.status.ordinal)
                output.writeInt(core.preflight.status.ordinal)
                output.writeInt(core.preflight.binCount)
                output.unsigned(core.preflight.minimumTicks)
                output.writeInt(core.windows.size)
                core.windows.forEach { window ->
                    output.snapshot(window.before)
                    output.snapshot(window.after)
                    output.cpus(window.workerAllowed)
                    output.writeLong(window.counterFrequencyHz.toLong())
                    output.writeInt(window.outcomes.size)
                    window.outcomes.forEach { output.outcome(it) }
                }
                output.writeInt(core.rounds.size)
                core.rounds.forEach { round ->
                    with(round.distance) {
                        listOf(firstZeros, targetZeros, secondZeros, jointTargetHigh).forEach(output::writeInt)
                    }
                    with(round.similarity) {
                        listOf(referenceSimilarity, targetSimilarity, controlSimilarity,
                            firstControlSimilarity, secondControlSimilarity, referenceMean, targetMean)
                            .forEach(output::writeDouble)
                    }
                    output.writeInt(round.support.size)
                    round.support.forEach { support ->
                        output.writeInt(support.retainedBins)
                        output.writeInt(support.firstMass)
                        output.writeInt(support.secondMass)
                    }
                }
            }
        }
        return buffer.toByteArray().also { require(it.size <= MAX_BYTES) }
    }

    fun decode(payload: ByteArray): KernelSuTimingObservation {
        require(payload.size in 1..MAX_BYTES)
        val input = DataInputStream(ByteArrayInputStream(payload))
        require(input.readInt() == PAYLOAD_VERSION)
        val collection = KernelSuTimingCollection.entries[input.index(KernelSuTimingCollection.entries.size)]
        val initial = input.snapshot()
        val final = if (input.readBoolean()) input.snapshot() else null
        val cleanup = input.readBoolean()
        val detail = input.detail()
        val attempts = List(input.count(16)) {
            val requested = input.readInt()
            val actual = input.readInt().also { require(it in -1..1023) }.takeIf { it >= 0 }
            val status = KernelSuTimingCoreStatus.entries[input.index(KernelSuTimingCoreStatus.entries.size)]
            val preflightStatus = KernelSuTimingPreflightStatus.entries[input.index(KernelSuTimingPreflightStatus.entries.size)]
            val preflight = KernelSuTimingPreflight(preflightStatus, input.count(10000), input.unsigned())
            val windows = List(input.count(4)) {
                val before = input.snapshot()
                val after = input.snapshot()
                val allowed = requireNotNull(input.cpus())
                val frequency = input.readLong().toULong()
                KernelSuTimingWindowEvidence(before, after, allowed, List(input.count(6)) { input.outcome() }, frequency)
            }
            val rounds = List(input.count(3)) {
                val distance = KernelSuTimingDistance(input.readInt(), input.readInt(), input.readInt(), input.readInt())
                val cosines = List(5) { input.readDouble().also {
                    require(it.isNaN() || (it.isFinite() && it in 0.0..1.000000000001))
                } }
                fun mean() = input.readDouble().also { require(it.isNaN() || (it.isFinite() && it >= 0.0)) }
                val similarity = KernelSuTimingSimilarity(cosines[0], cosines[1], cosines[2], cosines[3], cosines[4], mean(), mean())
                val support = List(input.count(6)) { KernelSuTimingSupport(input.readInt(), input.readInt(), input.readInt()) }
                KernelSuTimingAnalysis(distance, similarity, support)
            }
            KernelSuTimingCoreAttempt(requested, actual, status, rounds, preflight, windows)
        }
        require(input.available() == 0)
        return KernelSuTimingObservation(collection, initial, attempts, final, cleanup, detail)
    }

    private fun DataOutputStream.outcome(value: KernelSuTimingSyscallSummary) {
        writeInt(value.outcomes.size)
        value.outcomes.forEach { (code, count) -> writeLong(code); writeInt(count) }
        listOf(value.otherOutcomes, value.retriedSamples, value.totalRetries,
            value.maximumRetries, value.retryLimitSamples).forEach(::writeInt)
    }
    private fun DataInputStream.outcome(): KernelSuTimingSyscallSummary {
        val entries = List(count(8)) { readLong() to readInt() }
        require(entries.map { it.first }.distinct().size == entries.size)
        return KernelSuTimingSyscallSummary(entries.toMap(), readInt(), readInt(), readInt(), readInt(), readInt())
    }
    private fun DataOutputStream.snapshot(value: KernelSuTimingCpuSnapshot) {
        cpus(value.present); cpus(value.online); cpus(value.allowed); detail(value.detail)
    }
    private fun DataInputStream.snapshot() = KernelSuTimingCpuSnapshot(cpus(), cpus(), cpus(), detail())
    private fun DataOutputStream.cpus(value: List<Int>?) {
        writeBoolean(value != null)
        if (value == null) return
        val mask = ByteArray(128)
        value.forEach { mask[it / 8] = (mask[it / 8].toInt() or (1 shl (it % 8))).toByte() }
        write(mask)
    }
    private fun DataInputStream.cpus(): List<Int>? {
        if (!readBoolean()) return null
        val mask = ByteArray(128).also { readFully(it) }
        return (0..1023).filter { mask[it / 8].toInt() and (1 shl (it % 8)) != 0 }
    }
    private fun DataOutputStream.detail(value: String) {
        require(value.length <= MAX_DETAIL_LENGTH)
        writeUTF(value)
    }
    private fun DataInputStream.detail() = readUTF().also { require(it.length <= MAX_DETAIL_LENGTH) }
    private fun DataOutputStream.unsigned(value: ULong?) {
        writeBoolean(value != null)
        if (value != null) writeLong(value.toLong())
    }
    private fun DataInputStream.unsigned(): ULong? = if (readBoolean()) readLong().toULong() else null
    private fun DataInputStream.index(size: Int) = readInt().also { require(it in 0 until size) }
    private fun DataInputStream.count(maximum: Int) = readInt().also { require(it in 0..maximum) }
}
