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

/** Thrown when a payload arrived without a key the parser depends on. */
class NativePayloadContractViolation(
    message: String,
) : IllegalArgumentException(message)

/**
 * Checks that a line-oriented `KEY=value` payload still carries the keys its parser depends on.
 *
 * Parsers in this app stay deliberately lenient: an unknown key is ignored and a malformed record is
 * skipped, so a payload from a newer native layer keeps parsing against an older build. That
 * leniency has one cost - a key the native side renames or drops reads exactly like a device with
 * nothing to report, and the snapshot is marked collected. Naming the few keys the native side emits
 * unconditionally closes that gap without giving up the tolerance for additions.
 *
 * A blank payload never reaches here. It already means "the probe produced no evidence" and every
 * parser answers it with a default snapshot first, so this function has no case for it and treats it
 * like any other payload whose keys are absent.
 */
object NativePayloadContract {

    fun requireKeys(
        payload: String,
        vararg keys: String,
    ) {
        if (keys.isEmpty()) {
            return
        }

        val present = payload.lineSequence().mapNotNullTo(mutableSetOf()) { line ->
            val trimmed = line.trim()
            val separator = trimmed.indexOf('=')
            if (separator <= 0) null else trimmed.substring(0, separator)
        }

        val missing = keys.filterNot(present::contains)
        if (missing.isEmpty()) {
            return
        }

        val label = if (missing.size == 1) "key" else "keys"
        throw NativePayloadContractViolation(
            "missing required $label ${missing.joinToString()}",
        )
    }
}
