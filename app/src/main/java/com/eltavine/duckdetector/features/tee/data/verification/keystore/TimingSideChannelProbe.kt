package com.eltavine.duckdetector.features.tee.data.verification.keystore

import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge
import java.util.Locale
import kotlin.math.roundToInt

class TimingSideChannelProbe(
    private val registerTimerBridge: TeeRegisterTimerNativeBridge = TeeRegisterTimerNativeBridge(),
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(
        useStrongBox: Boolean = false,
        nativeSnapshot: NativeTeeSnapshot = NativeTeeSnapshot(),
    ): TimingSideChannelResult {
        val initialTimerMetadata = resolveTimerMetadata(nativeSnapshot)
        val measurementContext = bindMeasurementContext(initialTimerMetadata)
        val fallback = mutableListOf<String>().apply {
            initialTimerMetadata.timerFallbackReason?.let { add(it) }
            if (
                measurementContext.timerFallbackReason != null &&
                measurementContext.timerFallbackReason != initialTimerMetadata.timerFallbackReason
            ) {
                add(measurementContext.timerFallbackReason)
            }
        }

        return runCatching {
            val sessionResult = binderClient.openSession(useStrongBox = false)
            val session = sessionResult.session
                ?: throw IllegalStateException(
                    sessionResult.failureReason
                        ?: "Keystore2 private binder proxy session unavailable."
                )
            val aliases = binderClient.createTimingAliases()
            val attestedDescriptor = binderClient.createKeyDescriptor(aliases.attestedAlias)
            val nonAttestedDescriptor = binderClient.createKeyDescriptor(aliases.nonAttestedAlias)
            val attestKeyDescriptor = binderClient.createKeyDescriptor(aliases.attestKeyAlias)
            val warnings = mutableListOf<String>()
            var partialFailureReason: String? = null

            try {
                binderClient.generateAttestationKey(session.securityLevel, attestKeyDescriptor)
                binderClient.generateSigningKey(
                    securityLevel = session.securityLevel,
                    keyDescriptor = attestedDescriptor,
                    attestationKeyDescriptor = attestKeyDescriptor,
                    attest = true,
                )
                binderClient.generateSigningKey(
                    securityLevel = session.securityLevel,
                    keyDescriptor = nonAttestedDescriptor,
                    attestationKeyDescriptor = null,
                    attest = false,
                )

                val measurement = Measurement(
                    source = "keystore2_security_level_proxy",
                    detail = "Measured service.getKeyEntry timing on a TEE-only private binder proxy path; serviceProxy=${session.serviceProxyActive}, securityLevelProxy=${session.securityLevelProxyActive}, proxyInstalled=${session.proxyInstalled}",
                    measureMillis = { descriptor, timer -> measurePrivateGetKeyEntryMillis(session.service, descriptor, timer) },
                    timerSource = measurementContext.timeSource,
                )

                warmUpPair(measurement, attestedDescriptor, nonAttestedDescriptor, warnings)
                val pairedSeries = samplePairedSeries(measurement, attestedDescriptor, nonAttestedDescriptor, warnings)
                check(pairedSeries.attestedSamples.isNotEmpty() && pairedSeries.nonAttestedSamples.isNotEmpty()) {
                    "Timing side-channel measurement produced no samples"
                }
                partialFailureReason = listOfNotNull(pairedSeries.failureReason)
                    .joinToString("; ")
                    .takeIf { it.isNotBlank() }

                val avgAttested = pairedSeries.attestedSamples.averageOrNull()
                val avgNonAttested = pairedSeries.nonAttestedSamples.averageOrNull()
                val diff = if (avgAttested != null && avgNonAttested != null) avgAttested - avgNonAttested else null
                val suspicious = diff?.let(::isPositiveTimingSideChannelDiff) ?: false

                TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = suspicious,
                    sampleCount = pairedSeries.pairedSampleCount,
                    warmupCount = WARMUP_COUNT,
                    avgAttestedMillis = avgAttested,
                    avgNonAttestedMillis = avgNonAttested,
                    diffMillis = diff,
                    source = measurement.source,
                    timerSource = measurementContext.timerSource,
                    affinity = measurementContext.affinity,
                    fallback = buildList {
                        add(measurement.detail)
                        addAll(fallback)
                        addAll(warnings)
                    },
                    failureReason = partialFailureReason,
                    detail = buildTimingSideChannelDetail(
                        source = measurement.source,
                        timerSource = measurementContext.timerSource,
                        affinity = measurementContext.affinity,
                        avgAttestedMillis = avgAttested,
                        avgNonAttestedMillis = avgNonAttested,
                        diffMillis = diff,
                        suspicious = suspicious,
                        sampleCount = pairedSeries.pairedSampleCount,
                        warmupCount = WARMUP_COUNT,
                        measurementDetail = measurement.detail,
                        timerFallbackReason = measurementContext.timerFallbackReason,
                        partialFailureReason = partialFailureReason,
                    ),
                )
            } finally {
                binderClient.deleteKey(session.service, attestedDescriptor)
                binderClient.deleteKey(session.service, nonAttestedDescriptor)
                binderClient.deleteKey(session.service, attestKeyDescriptor)
            }
        }.getOrElse { throwable ->
            TimingSideChannelResult(
                probeRan = true,
                measurementAvailable = false,
                sampleCount = 0,
                warmupCount = WARMUP_COUNT,
                source = "keystore2_security_level_proxy",
                timerSource = measurementContext.timerSource,
                affinity = measurementContext.affinity,
                fallback = fallback,
                failureReason = throwable.message,
                detail = throwable.message ?: "Timing side-channel probe failed.",
            )
        }
    }

    private fun warmUpPair(
        measurement: Measurement,
        attestedDescriptor: Any,
        nonAttestedDescriptor: Any,
        warnings: MutableList<String>,
    ) {
        repeat(WARMUP_COUNT) { index ->
            runCatching { measurement.measureMillis(attestedDescriptor, measurement.timerSource) }
                .onFailure { warnings += "warmup.attested[$index]=${it.message ?: "failed"}" }
            runCatching { measurement.measureMillis(nonAttestedDescriptor, measurement.timerSource) }
                .onFailure { warnings += "warmup.nonAttested[$index]=${it.message ?: "failed"}" }
        }
    }

    private fun samplePairedSeries(
        measurement: Measurement,
        attestedDescriptor: Any,
        nonAttestedDescriptor: Any,
        warnings: MutableList<String>,
    ): PairedSampleSeries {
        val attestedSamples = mutableListOf<Double>()
        val nonAttestedSamples = mutableListOf<Double>()
        var firstFailure: String? = null
        repeat(LOOP_COUNT) { index ->
            val attested = runCatching { measurement.measureMillis(attestedDescriptor, measurement.timerSource) }
            val nonAttested = runCatching { measurement.measureMillis(nonAttestedDescriptor, measurement.timerSource) }

            if (attested.isSuccess && nonAttested.isSuccess) {
                attestedSamples += attested.getOrThrow()
                nonAttestedSamples += nonAttested.getOrThrow()
            } else {
                val failure = attested.exceptionOrNull()?.message
                    ?: nonAttested.exceptionOrNull()?.message
                    ?: "failed"
                if (firstFailure == null) {
                    firstFailure = failure
                }
                warnings += "sample.paired[$index]=$failure"
            }
        }
        return PairedSampleSeries(
            attestedSamples = attestedSamples,
            nonAttestedSamples = nonAttestedSamples,
            failureReason = firstFailure,
        )
    }

    private fun measurePrivateGetKeyEntryMillis(
        service: Any,
        descriptor: Any,
        timerSource: StableTimeSource,
    ): Double {
        val start = timerSource.readNs()
        binderClient.getKeyEntry(service, descriptor)
        val end = timerSource.readNs()
        return (end - start) / 1_000_000.0
    }

    private fun bindMeasurementContext(initialMetadata: TimerMetadata): TimerMetadata {
        val preferred = registerTimerBridge.selectPreferredTimer(requestCpu0Affinity = true)
        val affinity = when {
            preferred.affinityStatus != "not_requested" -> preferred.affinityStatus
            registerTimerBridge.bindCurrentThreadToCpu0() -> "bound_cpu0"
            else -> initialMetadata.affinity
        }
        val preferRegisterTimer = preferred.registerTimerAvailable && preferred.timerSource.contains("cntvct", ignoreCase = true)
        val timerFallbackReason = preferred.fallbackReason ?: initialMetadata.timerFallbackReason
        val timerSourceLabel = if (preferRegisterTimer) preferred.timerSource else "clock_monotonic"
        return TimerMetadata(
            timerSource = timerSourceLabel,
            affinity = affinity,
            timerFallbackReason = timerFallbackReason,
            timeSource = StableTimeSource(
                preferRegisterTimer = preferRegisterTimer,
                registerTimerSource = { registerTimerBridge.readRegisterTimerNs() },
                monotonicSource = { System.nanoTime() },
            ),
        )
    }

    private fun resolveTimerMetadata(nativeSnapshot: NativeTeeSnapshot): TimerMetadata {
        val timerSource = nativeSnapshot.trickyStoreTimerSource.ifBlank { "clock_monotonic" }
        val affinity = nativeSnapshot.trickyStoreAffinityStatus.ifBlank { "not_requested" }
        return TimerMetadata(
            timerSource = timerSource,
            affinity = affinity,
            timerFallbackReason = nativeSnapshot.trickyStoreTimerFallbackReason,
            timeSource = StableTimeSource(
                preferRegisterTimer = false,
                registerTimerSource = { null },
                monotonicSource = { System.nanoTime() },
            ),
        )
    }

    private fun List<Double>.averageOrNull(): Double? = if (isEmpty()) null else average()

    private data class Measurement(
        val source: String,
        val detail: String,
        val measureMillis: (Any, StableTimeSource) -> Double,
        val timerSource: StableTimeSource,
    )

    private data class PairedSampleSeries(
        val attestedSamples: List<Double>,
        val nonAttestedSamples: List<Double>,
        val failureReason: String? = null,
    ) {
        val pairedSampleCount: Int
            get() = minOf(attestedSamples.size, nonAttestedSamples.size)
    }

    private data class TimerMetadata(
        val timerSource: String,
        val affinity: String,
        val timerFallbackReason: String? = null,
        val timeSource: StableTimeSource,
    )

    companion object {
        private const val WARMUP_COUNT = 5
        private const val LOOP_COUNT = 1000
    }
}

internal data class StableTimeSource(
    private val preferRegisterTimer: Boolean,
    private val registerTimerSource: () -> Long?,
    private val monotonicSource: () -> Long,
) {
    fun readNs(): Long = stableTimerReadNs(preferRegisterTimer, registerTimerSource, monotonicSource)
}

internal fun stableTimerReadNs(
    preferRegisterTimer: Boolean,
    registerTimerSource: () -> Long?,
    monotonicSource: () -> Long,
): Long {
    if (preferRegisterTimer) {
        return registerTimerSource() ?: throw IllegalStateException(
            "Register timer read failed while arm64_cntvct was selected as the preferred timing source.",
        )
    }
    return monotonicSource()
}

internal fun isPositiveTimingSideChannelDiff(diffMillis: Double): Boolean {
    return diffMillis > 0.3 || diffMillis < -0.3
}

internal fun buildTimingSideChannelDetail(
    source: String,
    timerSource: String,
    affinity: String,
    avgAttestedMillis: Double?,
    avgNonAttestedMillis: Double?,
    diffMillis: Double?,
    suspicious: Boolean,
    sampleCount: Int,
    warmupCount: Int,
    measurementDetail: String,
    timerFallbackReason: String?,
    partialFailureReason: String?,
): String {
    return buildString {
        append("semantics=securityLevel.getKeyEntry")
        append(", source=")
        append(source)
        append(", timer=")
        append(timerSource)
        append(", affinity=")
        append(affinity)
        append(", avgAttested=")
        append(avgAttestedMillis?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append("ms, avgNonAttested=")
        append(avgNonAttestedMillis?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append("ms, diff=")
        append(diffMillis?.let { String.format(Locale.US, "%.3f", it) } ?: "n/a")
        append("ms, suspicious=")
        append(suspicious)
        append(", threshold=diff > 0.3ms || diff < -0.3ms")
        append(", warmup=")
        append(warmupCount)
        append(", samples=")
        append(sampleCount)
        append(". ")
        append(measurementDetail)
        timerFallbackReason?.let {
            append(" timerFallback=")
            append(it)
        }
        partialFailureReason?.let {
            append(" partialFailure=")
            append(it)
        }
    }
}

internal fun pairedDiffSeries(
    attestedSamples: List<Double>,
    nonAttestedSamples: List<Double>,
): List<Double> {
    val pairedCount = minOf(attestedSamples.size, nonAttestedSamples.size)
    return buildList(pairedCount) {
        repeat(pairedCount) { index ->
            add(attestedSamples[index] - nonAttestedSamples[index])
        }
    }
}

data class TimingSideChannelResult(
    val probeRan: Boolean,
    val measurementAvailable: Boolean = false,
    val suspicious: Boolean = false,
    val sampleCount: Int = 0,
    val warmupCount: Int = 0,
    val avgAttestedMillis: Double? = null,
    val avgNonAttestedMillis: Double? = null,
    val diffMillis: Double? = null,
    val source: String = "unknown",
    val timerSource: String = "unknown",
    val affinity: String = "unknown",
    val fallback: List<String> = emptyList(),
    val failureReason: String? = null,
    val detail: String,
) {
    fun avgAttestedMicros(): Int? = avgAttestedMillis?.times(1_000)?.roundToInt()

    fun avgNonAttestedMicros(): Int? = avgNonAttestedMillis?.times(1_000)?.roundToInt()

    fun diffMicros(): Int? = diffMillis?.times(1_000)?.roundToInt()
}
