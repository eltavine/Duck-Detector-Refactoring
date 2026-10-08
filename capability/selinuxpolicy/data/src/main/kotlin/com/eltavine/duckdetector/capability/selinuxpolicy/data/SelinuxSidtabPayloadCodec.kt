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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.native.NativePayloadCodec

/** This nested payload keeps SID-table evidence separate from the existing context oracle. */
internal object SelinuxSidtabPayloadCodec {
    fun decode(raw: String): SelinuxSidtabSnapshot {
        val values = linkedMapOf<String, String>()
        raw.lineSequence().filter { it.isNotBlank() }.forEach { line ->
            if (!line.contains('=')) return malformed()
            val key = line.substringBefore('=')
            if (values.put(key, NativePayloadCodec.decodeValue(line.substringAfter('='))) != null) return malformed()
        }
        if (values["SCHEMA"] != "1") return malformed()
        val collection = SelinuxSidtabCollection.entries.firstOrNull { it.name == values["STATE"] }
            ?: return malformed()
        val step = SelinuxSidtabStep.entries.firstOrNull { it.name == values["STEP"] } ?: return malformed()
        val attempted = when (values["ATTEMPTED"]) { "0" -> false; "1" -> true; else -> return malformed() }
        fun number(key: String): Long? = values[key]?.toLongOrNull()?.takeIf { it >= 0 }
        fun error(key: String): Int? = values[key]?.toIntOrNull()?.takeIf { it >= 0 }
        return SelinuxSidtabSnapshot(
            collection = collection,
            attempted = attempted,
            step = step,
            errno = error("ERRNO"),
            completedRounds = error("COMPLETED_ROUNDS") ?: 0,
            canonicalMismatch = values["CANONICAL_MISMATCH"] != "0",
            identityChanged = values["IDENTITY_CHANGED"] != "0",
            uid = error("UID"),
            pid = error("PID"),
            capturedUptimeMs = number("CAPTURED_UPTIME_MS"),
            carrierContext = values["CARRIER"],
            kernelRelease = values["KERNEL_RELEASE"],
            childEnd = SelinuxSidtabChildEnd.entries.firstOrNull { it.name == values["CHILD_END"] },
            signal = error("SIGNAL"),
            failureReason = values["FAILURE_REASON"],
            rounds = (0 until 2).mapNotNull { index ->
                val prefix = "R${index}_"
                if (values.keys.none { it.startsWith(prefix) }) return@mapNotNull null
                SelinuxSidtabRound(
                    beforeControls = number(prefix + "BEFORE_CONTROLS"),
                    before = number(prefix + "BEFORE"),
                    afterContext = number(prefix + "AFTER_CONTEXT"),
                    afterAttr = number(prefix + "AFTER_ATTR"),
                    afterRepeat = number(prefix + "AFTER_REPEAT"),
                    idleEnd = number(prefix + "IDLE_END"),
                    positiveErrno = error(prefix + "POSITIVE_ERRNO"),
                    negativeErrno = error(prefix + "NEGATIVE_ERRNO"),
                    attrNegativeErrno = error(prefix + "ATTR_NEGATIVE_ERRNO"),
                    samples = (0 until 4).map { sample ->
                        val key = prefix + "S${sample}_"
                        SelinuxSidtabSample(
                            context = values[key + "CONTEXT"].orEmpty(),
                            contextErrno = error(key + "CONTEXT_ERRNO"),
                            attrErrno = error(key + "ATTR_ERRNO"),
                            repeatErrno = error(key + "REPEAT_ERRNO"),
                        )
                    },
                )
            },
        )
    }

    fun encode(snapshot: SelinuxSidtabSnapshot): String = buildString {
        fun entry(key: String, value: Any?) {
            if (value != null) append(key).append('=').append(NativePayloadCodec.encodeValue(value.toString())).append('\n')
        }
        entry("SCHEMA", 1)
        entry("STATE", snapshot.collection.name)
        entry("ATTEMPTED", if (snapshot.attempted) 1 else 0)
        entry("STEP", snapshot.step.name)
        entry("ERRNO", snapshot.errno)
        entry("COMPLETED_ROUNDS", snapshot.completedRounds)
        entry("CANONICAL_MISMATCH", if (snapshot.canonicalMismatch) 1 else 0)
        entry("IDENTITY_CHANGED", if (snapshot.identityChanged) 1 else 0)
        entry("UID", snapshot.uid)
        entry("PID", snapshot.pid)
        entry("CAPTURED_UPTIME_MS", snapshot.capturedUptimeMs)
        entry("CARRIER", snapshot.carrierContext)
        entry("KERNEL_RELEASE", snapshot.kernelRelease)
        entry("CHILD_END", snapshot.childEnd?.name)
        entry("SIGNAL", snapshot.signal)
        entry("FAILURE_REASON", snapshot.failureReason)
        snapshot.rounds.forEachIndexed { index, round ->
            val prefix = "R${index}_"
            entry(prefix + "BEFORE_CONTROLS", round.beforeControls)
            entry(prefix + "BEFORE", round.before)
            entry(prefix + "AFTER_CONTEXT", round.afterContext)
            entry(prefix + "AFTER_ATTR", round.afterAttr)
            entry(prefix + "AFTER_REPEAT", round.afterRepeat)
            entry(prefix + "IDLE_END", round.idleEnd)
            entry(prefix + "POSITIVE_ERRNO", round.positiveErrno)
            entry(prefix + "NEGATIVE_ERRNO", round.negativeErrno)
            entry(prefix + "ATTR_NEGATIVE_ERRNO", round.attrNegativeErrno)
            round.samples.forEachIndexed { sampleIndex, sample ->
                val key = prefix + "S${sampleIndex}_"
                entry(key + "CONTEXT", sample.context)
                entry(key + "CONTEXT_ERRNO", sample.contextErrno)
                entry(key + "ATTR_ERRNO", sample.attrErrno)
                entry(key + "REPEAT_ERRNO", sample.repeatErrno)
            }
        }
    }

    private fun malformed(): SelinuxSidtabSnapshot = SelinuxSidtabSnapshot(
        collection = SelinuxSidtabCollection.UNAVAILABLE,
        failureReason = "SID-table payload was malformed or used an unsupported schema.",
    )
}
