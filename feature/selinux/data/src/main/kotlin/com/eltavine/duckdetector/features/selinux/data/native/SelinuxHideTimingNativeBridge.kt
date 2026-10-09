/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package com.eltavine.duckdetector.features.selinux.data.native

import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

internal enum class SelinuxHideTimingState { CANDIDATE, NO_SIGNAL, UNAVAILABLE }

internal data class SelinuxHideTimingSnapshot(
    val state: SelinuxHideTimingState = SelinuxHideTimingState.UNAVAILABLE,
    val pairs: Int = 0,
    val aMedianNs: Long = 0,
    val bMedianNs: Long = 0,
    val deltaP10Ns: Long = 0,
    val deltaMedianNs: Long = 0,
    val deltaP90Ns: Long = 0,
    val firstHalfNs: Long = 0,
    val secondHalfNs: Long = 0,
    val aSlower: Int = 0,
    val contextLength: Int = 0,
    val reason: String? = null,
)

internal open class SelinuxHideTimingNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    open fun collectSnapshot(): SelinuxHideTimingSnapshot = collector.collect(
        readPayload = ::nativeCollectTimingSnapshot,
        parse = ::parse,
        unavailable = { status -> SelinuxHideTimingSnapshot(reason = status.explain("attr/current timing unavailable")) },
    )

    internal fun parse(raw: String): SelinuxHideTimingSnapshot {
        NativePayloadContract.requireKeys(raw, "STATE")
        val fields = raw.lineSequence()
            .mapNotNull { line ->
                val i = line.indexOf('=')
                if (i <= 0) null else line.take(i) to line.drop(i + 1)
            }.toMap()
        val state = when (fields["STATE"]) {
            "CANDIDATE" -> SelinuxHideTimingState.CANDIDATE
            "NO_SIGNAL" -> SelinuxHideTimingState.NO_SIGNAL
            "UNAVAILABLE" -> return SelinuxHideTimingSnapshot(reason = fields["REASON"] ?: "Probe unavailable")
            else -> error("Unexpected timing state")
        }
        NativePayloadContract.requireKeys(
            raw, "PAIRS", "A_MEDIAN_NS", "B_MEDIAN_NS", "DELTA_P10_NS", "DELTA_MEDIAN_NS",
            "DELTA_P90_NS", "HALVES_NS", "A_SLOWER", "CONTEXT_LENGTH", "ERRORS",
        )
        require(fields["ERRORS"] == "both EACCES") { "Timing writes were not both denied" }
        val halves = fields.getValue("HALVES_NS").split(',')
        require(halves.size == 2)
        val pairs = fields.getValue("PAIRS").toInt()
        val slower = fields.getValue("A_SLOWER").toInt()
        require(pairs in 16..4096 && slower in 0..pairs)
        return SelinuxHideTimingSnapshot(
            state = state,
            pairs = pairs,
            aMedianNs = fields.getValue("A_MEDIAN_NS").toLong(),
            bMedianNs = fields.getValue("B_MEDIAN_NS").toLong(),
            deltaP10Ns = fields.getValue("DELTA_P10_NS").toLong(),
            deltaMedianNs = fields.getValue("DELTA_MEDIAN_NS").toLong(),
            deltaP90Ns = fields.getValue("DELTA_P90_NS").toLong(),
            firstHalfNs = halves[0].toLong(),
            secondHalfNs = halves[1].toLong(),
            aSlower = slower,
            contextLength = fields.getValue("CONTEXT_LENGTH").toInt(),
        )
    }

    private external fun nativeCollectTimingSnapshot(): String
}
