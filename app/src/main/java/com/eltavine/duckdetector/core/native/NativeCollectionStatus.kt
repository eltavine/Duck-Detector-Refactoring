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

package com.eltavine.duckdetector.core.native

/**
 * Why a native snapshot does or does not carry usable evidence.
 *
 * A detector that reports "nothing found" after its probes failed to run produces a false
 * negative, which is the most expensive kind of wrong answer this app can give. Native-backed
 * snapshots therefore carry an outcome next to their data instead of silently degrading to
 * default field values.
 */
enum class NativeCollectionOutcome {

    /** The bridge produced a payload and the parser accepted it. */
    COLLECTED,

    /** `libduckdetector.so` never loaded, so no probe behind this snapshot ran at all. */
    LIBRARY_UNAVAILABLE,

    /** The JNI entry point threw or aborted before returning a payload. */
    BRIDGE_FAILED,

    /** A payload arrived but the parser rejected it, meaning the wire contract drifted. */
    PAYLOAD_REJECTED,

    ;

    /** Only [COLLECTED] snapshots may be read as statements about the device. */
    val isTrustworthy: Boolean
        get() = this == COLLECTED
}

/**
 * A collection [outcome] together with an auditable [detail] describing how it was reached.
 *
 * [detail] is deliberately a human-readable diagnostic rather than a structured cause: it is meant
 * for the exported report, where a reader needs to tell "StrongBox is absent" apart from "we could
 * not ask about StrongBox".
 */
data class NativeCollectionStatus(
    val outcome: NativeCollectionOutcome = NativeCollectionOutcome.COLLECTED,
    val detail: String = "",
) {

    val isTrustworthy: Boolean
        get() = outcome.isTrustworthy

    /**
     * Builds the report line for a snapshot that carries no evidence.
     *
     * [summary] names the snapshot that is missing and must not end in punctuation; the detail, when
     * one was captured, follows it. Every repository shares this one rule so that an unloadable
     * library, an aborted probe, and an unparsable payload never read identically in an exported
     * report regardless of which detector produced them.
     */
    fun explain(summary: String): String {
        return if (detail.isBlank()) "$summary." else "$summary: $detail"
    }

    companion object {

        val Collected: NativeCollectionStatus = NativeCollectionStatus()

        fun failed(
            outcome: NativeCollectionOutcome,
            cause: Throwable,
        ): NativeCollectionStatus {
            val type = cause::class.java.simpleName
            val message = cause.message?.takeIf(String::isNotBlank)
            return NativeCollectionStatus(
                outcome = outcome,
                detail = if (message == null) type else "$type: $message",
            )
        }
    }
}
