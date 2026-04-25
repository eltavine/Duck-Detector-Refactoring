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

import com.eltavine.duckdetector.features.tee.data.native.NativeTeeSnapshot
import com.eltavine.duckdetector.features.tee.data.native.TeeRegisterTimerNativeBridge
import java.util.Locale
import kotlin.math.roundToInt

/**
 * 在同一组私有 binder 代理语义下对 attested / non-attested key 做配对测量，保证 timing 差值和 skip 栈都来自同一条隐藏接口路径。
 * Measures attested / non-attested keys under the same private binder proxy semantics so both timing deltas and skip stacks come from one hidden-interface path.
 */
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
        val warmupFailures = CapturedThrowableCollector()
        var gatewayFailures = emptyList<CapturedThrowableRecord>()
        val fallback = mutableListOf<String>().apply {
            initialTimerMetadata.timerFallbackReason?.let { add(it) }
            if (
                measurementContext.timerFallbackReason != null &&
                measurementContext.timerFallbackReason != initialTimerMetadata.timerFallbackReason
            ) {
                add(measurementContext.timerFallbackReason)
            }
        }
        fun describeFailure(throwable: Throwable): String = binderClient.describeThrowable(throwable)

        return runCatching {
            val sessionResult = binderClient.openSession(useStrongBox = useStrongBox)
            gatewayFailures = sessionResult.capturedFailures
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
            var effectiveAttestedDescriptor = attestedDescriptor
            var effectiveNonAttestedDescriptor = nonAttestedDescriptor
            var effectiveAttestKeyDescriptor = attestKeyDescriptor

            try {
                // 生成阶段一旦返回 KEY_ID 风格 descriptor，后续 warmup/sample/delete 都必须切到 follow-up descriptor，保证测的是同一个真实 key handle。
                // Once generateKey returns a KEY_ID-style descriptor, every warmup/sample/delete step must switch to that follow-up descriptor to stay on the same real key handle.
                val attestationKeyMetadata = binderClient.generateAttestationKey(
                    session.securityLevel,
                    attestKeyDescriptor,
                )
                effectiveAttestKeyDescriptor = binderClient.resolveFollowUpDescriptor(
                    requestedDescriptor = attestKeyDescriptor,
                    keyMetadataOrResponse = attestationKeyMetadata,
                )
                val attestedKeyMetadata = binderClient.generateSigningKey(
                    securityLevel = session.securityLevel,
                    keyDescriptor = attestedDescriptor,
                    attestationKeyDescriptor = effectiveAttestKeyDescriptor,
                    attest = true,
                )
                effectiveAttestedDescriptor = binderClient.resolveFollowUpDescriptor(
                    requestedDescriptor = attestedDescriptor,
                    keyMetadataOrResponse = attestedKeyMetadata,
                )
                val nonAttestedKeyMetadata = binderClient.generateSigningKey(
                    securityLevel = session.securityLevel,
                    keyDescriptor = nonAttestedDescriptor,
                    attestationKeyDescriptor = null,
                    attest = false,
                )
                effectiveNonAttestedDescriptor = binderClient.resolveFollowUpDescriptor(
                    requestedDescriptor = nonAttestedDescriptor,
                    keyMetadataOrResponse = nonAttestedKeyMetadata,
                )

                val measurement = Measurement(
                    source = "keystore2_security_level_proxy",
                    detail = "Measured service.getKeyEntry timing on a TEE-only private binder proxy path; serviceProxy=${session.serviceProxyActive}, securityLevelProxy=${session.securityLevelProxyActive}, proxyInstalled=${session.proxyInstalled}",
                    measureMillis = { descriptor, timer -> measurePrivateGetKeyEntryMillis(session.service, descriptor, timer) },
                    timerSource = measurementContext.timeSource,
                )

                // warmup 的栈最接近真实“样本为何无法测量”的原因；只有 warmup 没留下东西时，才退回整条私有代理链路的诊断栈。
                // Warmup stacks best represent why the measurement could not start; only when warmup captures nothing do we fall back to session-wide proxy diagnostics.
                warmUpPair(
                    measurement = measurement,
                    attestedDescriptor = effectiveAttestedDescriptor,
                    nonAttestedDescriptor = effectiveNonAttestedDescriptor,
                    warnings = warnings,
                    warmupFailures = warmupFailures,
                    describeFailure = ::describeFailure,
                )
                val pairedSeries = samplePairedSeries(
                    measurement = measurement,
                    attestedDescriptor = effectiveAttestedDescriptor,
                    nonAttestedDescriptor = effectiveNonAttestedDescriptor,
                    warnings = warnings,
                    describeFailure = ::describeFailure,
                )
                val filteredSeries = pairedSeries.filterOutlierPairs()
                check(pairedSeries.attestedSamples.isNotEmpty() && pairedSeries.nonAttestedSamples.isNotEmpty()) {
                    "Timing side-channel measurement produced no samples"
                }
                partialFailureReason = listOfNotNull(pairedSeries.failureReason)
                    .joinToString("; ")
                    .takeIf { it.isNotBlank() }

                val avgAttested = filteredSeries.attestedSamples.averageOrNull()
                val avgNonAttested = filteredSeries.nonAttestedSamples.averageOrNull()
                val diff = if (avgAttested != null && avgNonAttested != null) avgAttested - avgNonAttested else null
                val suspicious = diff?.let(::isPositiveTimingSideChannelDiff) ?: false
                val filteredCount = pairedSeries.pairedSampleCount - filteredSeries.pairedSampleCount
                val filteringNote = if (filteredCount > 0) {
                    "filteredBadSamples=$filteredCount/${pairedSeries.pairedSampleCount}"
                } else {
                    null
                }

                TimingSideChannelResult(
                    probeRan = true,
                    measurementAvailable = true,
                    suspicious = suspicious,
                    sampleCount = filteredSeries.pairedSampleCount,
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
                    stackCopyPayload = selectTimingSideChannelCopyPayload(
                        warmupFailures = warmupFailures.snapshot(),
                        gatewayFailures = session.diagnosticsCollector.snapshot(),
                    ),
                    detail = buildTimingSideChannelDetail(
                        source = measurement.source,
                        timerSource = measurementContext.timerSource,
                        affinity = measurementContext.affinity,
                        avgAttestedMillis = avgAttested,
                        avgNonAttestedMillis = avgNonAttested,
                        diffMillis = diff,
                        suspicious = suspicious,
                        sampleCount = filteredSeries.pairedSampleCount,
                        warmupCount = WARMUP_COUNT,
                        measurementDetail = measurement.detail,
                        timerFallbackReason = measurementContext.timerFallbackReason,
                        partialFailureReason = listOfNotNull(partialFailureReason, filteringNote)
                            .joinToString("; ")
                            .takeIf { it.isNotBlank() },
                    ),
                )
            } finally {
                cleanupDescriptors(
                    service = session.service,
                    descriptors = listOf(
                        effectiveAttestedDescriptor,
                        attestedDescriptor,
                        effectiveNonAttestedDescriptor,
                        nonAttestedDescriptor,
                        effectiveAttestKeyDescriptor,
                        attestKeyDescriptor,
                    ),
                )
                gatewayFailures = session.diagnosticsCollector.snapshot()
                binderClient.closeSession(session)
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
                failureReason = describeFailure(throwable),
                stackCopyPayload = selectTimingSideChannelCopyPayload(
                    warmupFailures = warmupFailures.snapshot(),
                    gatewayFailures = gatewayFailures,
                ),
                detail = describeFailure(throwable),
            )
        }
    }

    private fun warmUpPair(
        measurement: Measurement,
        attestedDescriptor: Any,
        nonAttestedDescriptor: Any,
        warnings: MutableList<String>,
        warmupFailures: CapturedThrowableCollector,
        describeFailure: (Throwable) -> String,
    ) {
        repeat(WARMUP_COUNT) { index ->
            runCatching { measurement.measureMillis(attestedDescriptor, measurement.timerSource) }
                .onFailure {
                    val phase = "warmup.attested[$index]"
                    val summary = describeFailure(it)
                    warmupFailures.record(phase = phase, summary = summary, throwable = it)
                    warnings += "$phase=$summary"
                }
            runCatching { measurement.measureMillis(nonAttestedDescriptor, measurement.timerSource) }
                .onFailure {
                    val phase = "warmup.nonAttested[$index]"
                    val summary = describeFailure(it)
                    warmupFailures.record(phase = phase, summary = summary, throwable = it)
                    warnings += "$phase=$summary"
                }
        }
    }

    private fun samplePairedSeries(
        measurement: Measurement,
        attestedDescriptor: Any,
        nonAttestedDescriptor: Any,
        warnings: MutableList<String>,
        describeFailure: (Throwable) -> String,
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
                val failure = attested.exceptionOrNull()?.let(describeFailure)
                    ?: nonAttested.exceptionOrNull()?.let(describeFailure)
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

    private fun cleanupDescriptors(
        service: Any,
        descriptors: List<Any>,
    ) {
        descriptors
            .distinctBy { System.identityHashCode(it) }
            .forEach { descriptor ->
                binderClient.deleteKey(service, descriptor)
            }
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

        fun filterOutlierPairs(): PairedSampleSeries {
            val pairedDiffs = pairedDiffSeries(attestedSamples, nonAttestedSamples)
            if (pairedDiffs.size < 8) {
                return this
            }
            val median = pairedDiffs.sorted()[pairedDiffs.size / 2]
            val absoluteDeviation = pairedDiffs.map { kotlin.math.abs(it - median) }.sorted()
            val mad = absoluteDeviation[absoluteDeviation.size / 2]
            if (mad == 0.0) {
                return this
            }
            val keepIndices = pairedDiffs.mapIndexedNotNull { index, diff ->
                if (kotlin.math.abs(diff - median) <= mad * 6.0) index else null
            }
            if (keepIndices.size == pairedDiffs.size || keepIndices.isEmpty()) {
                return this
            }
            return PairedSampleSeries(
                attestedSamples = keepIndices.map { attestedSamples[it] },
                nonAttestedSamples = keepIndices.map { nonAttestedSamples[it] },
                failureReason = failureReason,
            )
        }
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
    return diffMillis > TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS ||
        diffMillis < -TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS
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
        append("semantics=service.getKeyEntry")
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
        append(", threshold=diff > ")
        append(String.format(Locale.US, "%.1f", TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS))
        append("ms || diff < -")
        append(String.format(Locale.US, "%.1f", TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS))
        append("ms")
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

internal fun selectTimingSideChannelCopyPayload(
    warmupFailures: List<CapturedThrowableRecord>,
    gatewayFailures: List<CapturedThrowableRecord>,
): String {
    // 复制入口优先给 warmup 失败，因为这部分最贴近 skip 语义；gateway 栈只作为“warmup 没抓到但会话内部确实报错了”的兜底证据。
    // Prefer warmup failures for copy because they best explain skip semantics; gateway failures are the fallback evidence when warmup stayed silent.
    val selected = if (warmupFailures.isNotEmpty()) warmupFailures else gatewayFailures
    if (selected.isEmpty()) {
        return "null"
    }
    return selected.joinToString(separator = "\n\n---\n\n") { record ->
        buildString {
            append("phase=")
            append(record.phase)
            append('\n')
            append("summary=")
            append(record.summary)
            append('\n')
            append("occurrences=")
            append(record.occurrenceCount)
            append("\n\n")
            append(record.stackTrace)
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
    // 这里保存的是给人工静态审查用的原始异常 payload，不参与阈值计算，但会驱动 skip->patch-mode 的静态签名判定。
    // This stores the raw exception payload for human/static review; it does not affect timing math directly, but it does drive skip-to-patch-mode signature matching.
    val stackCopyPayload: String = "null",
    val detail: String,
) {
    fun avgAttestedMicros(): Int? = avgAttestedMillis?.times(1_000)?.roundToInt()

    fun avgNonAttestedMicros(): Int? = avgNonAttestedMillis?.times(1_000)?.roundToInt()

    fun diffMicros(): Int? = diffMillis?.times(1_000)?.roundToInt()
}

// 阈值故意保持单点常量，避免 probe/reducer/test 三处漂移。 / Keep the threshold as a single source of truth so probe, reducer, and tests cannot drift.
internal const val TIMING_SIDE_CHANNEL_THRESHOLD_MILLIS = 0.2
