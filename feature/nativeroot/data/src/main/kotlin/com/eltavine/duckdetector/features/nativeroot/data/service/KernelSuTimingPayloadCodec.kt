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
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

internal object KernelSuTimingPayloadCodec {
    private const val PAYLOAD_VERSION = 1
    private const val MAX_BYTES = 16384
    private const val MAX_DETAIL_LENGTH = 160

    fun encode(value: KernelSuTimingObservation): ByteArray {
        val buffer = ByteArrayOutputStream()
        DataOutputStream(buffer).use { output ->
            output.writeInt(PAYLOAD_VERSION)
            output.writeInt(value.collection.ordinal)
            output.writeInt(value.preflight.status.ordinal)
            output.writeInt(value.preflight.binCount)
            output.unsigned(value.preflight.minimumTicks)
            output.writeInt(value.enumeratedCpus.size)
            value.enumeratedCpus.forEach(output::writeInt)
            output.unsigned(value.counterFrequencyHz)
            output.writeBoolean(value.cleanupCompleted)
            require(value.detail.length <= MAX_DETAIL_LENGTH)
            output.writeUTF(value.detail)
            output.writeInt(value.attempts.size)
            value.attempts.forEach { core ->
                output.writeInt(core.requestedCpu)
                output.writeInt(core.actualCpu ?: -1)
                output.writeInt(core.status.ordinal)
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
        val preflightStatus = KernelSuTimingPreflightStatus.entries[input.index(KernelSuTimingPreflightStatus.entries.size)]
        val bins = input.readInt().also { require(it in 0..10000) }
        val preflight = KernelSuTimingPreflight(preflightStatus, bins, input.unsigned())
        require(preflightStatus != KernelSuTimingPreflightStatus.ACCEPTED ||
            (bins in 1..750 && preflight.minimumTicks?.let { it <= 135uL } == true))
        val cpus = List(input.count(16)) { input.readInt() }
        val frequency = input.unsigned()
        val cleanup = input.readBoolean()
        val detail = input.readUTF().also { require(it.length <= MAX_DETAIL_LENGTH) }
        val attempts = List(input.count(16)) {
            val requested = input.readInt()
            val actual = input.readInt().also { require(it in -1..1023) }.takeIf { it >= 0 }
            val status = KernelSuTimingCoreStatus.entries[input.index(KernelSuTimingCoreStatus.entries.size)]
            val rounds = List(input.count(3)) {
                val distance = KernelSuTimingDistance(input.readInt(), input.readInt(), input.readInt(), input.readInt())
                val cosines = List(5) { input.readDouble().also { require(it.isFinite() && it in 0.0..1.000000000001) } }
                fun mean() = input.readDouble().also { require(it.isNaN() || (it.isFinite() && it >= 0.0)) }
                KernelSuTimingAnalysis(distance, KernelSuTimingSimilarity(cosines[0], cosines[1], cosines[2],
                    cosines[3], cosines[4], mean(), mean()))
            }
            KernelSuTimingCoreAttempt(requested, actual, status, rounds)
        }
        require(input.available() == 0)
        return KernelSuTimingObservation(collection, preflight, cpus, attempts, frequency, cleanup, detail)
    }

    private fun DataOutputStream.unsigned(value: ULong?) {
        writeBoolean(value != null)
        if (value != null) writeLong(value.toLong())
    }
    private fun DataInputStream.unsigned(): ULong? = if (readBoolean()) readLong().toULong() else null
    private fun DataInputStream.index(size: Int) = readInt().also { require(it in 0 until size) }
    private fun DataInputStream.count(maximum: Int) = readInt().also { require(it in 0..maximum) }
}
