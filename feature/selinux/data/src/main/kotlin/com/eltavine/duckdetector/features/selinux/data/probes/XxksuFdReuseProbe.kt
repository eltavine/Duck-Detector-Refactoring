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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle

/**
 * Interprets the native, app_zygote-parent same-FD SELinuxFS record.
 *
 * Stock simple_transaction_get() consumes the descriptor before parsing.
 * The xxksu SELinux Hide hook can return EINVAL before it, so a second write to the
 * same FD may succeed (valid context) or return EINVAL (invalid context),
 * rather than EBUSY. This is a specific implementation fingerprint, not
 * universal proof of xxksu or a secure device.
 */
internal object XxksuFdReuseProbe {
    private const val EINVAL = 22
    private const val EBUSY = 16
    private const val PREFIX = "u:r:app_zygote:s0"
    private val casePattern = Regex(
        """^fd_reuse_case=(\w+) open_errno=(-?\d+) first_ret=(-?\d+) errno=(-?\d+) second_ret=(-?\d+) errno=(-?\d+)$""",
    )

    private data class Writes(
        val openError: Int,
        val firstBytes: Int,
        val firstError: Int,
        val secondBytes: Int,
        val secondError: Int,
    ) {
        fun isSequence(firstBytes: Int, firstError: Int, secondBytes: Int, secondError: Int) =
            openError == 0 && this.firstBytes == firstBytes && this.firstError == firstError &&
                this.secondBytes == secondBytes && this.secondError == secondError

        fun describe(): String =
            "first=$firstBytes/errno=$firstError second=$secondBytes/errno=$secondError open_errno=$openError"
    }

    private fun readCases(raw: String): Map<String, Writes>? {
        val result = mutableMapOf<String, Writes>()
        raw.lineSequence().forEach { line ->
            if (!line.startsWith("fd_reuse_case=")) return@forEach
            val parts = casePattern.matchEntire(line) ?: return null
            val values = parts.groupValues.drop(2).map { it.toIntOrNull() ?: return null }
            if (result.put(
                    parts.groupValues[1],
                    Writes(values[0], values[1], values[2], values[3], values[4]),
                ) != null
            ) return null
        }
        return result
    }

    fun interpret(raw: String?): SelinuxCheckResult {
        fun result(status: String, detected: Boolean? = null, reason: String): SelinuxCheckResult =
            SelinuxCheckResult(
                method = SelinuxOracle.XXKSU_FD_REUSE.label,
                oracle = SelinuxOracle.XXKSU_FD_REUSE,
                status = status,
                // Not observed is not proof that a hook or root is absent.
                isSecure = if (detected == true) false else null,
                permissionDenied = false,
                details = reason,
            )

        if (raw.isNullOrBlank()) return result("Unavailable", reason = "No app_zygote parent same-FD record.")
        if (raw.length > 8192) return result("Inconclusive", reason = "Oversized native transaction report.")
        val lines = raw.lineSequence().toList()
        val carrier = lines.singleOrNull { it.startsWith("fd_reuse_carrier=") }
            ?.substringAfter("fd_reuse_carrier=")?.substringBefore(" read_errno=")
        val uid = lines.singleOrNull { it.startsWith("fd_reuse_pid=") }
            ?.substringAfter(" fd_reuse_uid=")?.toIntOrNull()
        val pid = lines.singleOrNull { it.startsWith("fd_reuse_pid=") }
            ?.substringAfter("fd_reuse_pid=")?.substringBefore(' ')?.toIntOrNull()
        if (pid == null || pid <= 0 || uid == null || uid < 10000 ||
            carrier == null || (carrier != PREFIX && !carrier.startsWith("$PREFIX:"))
        ) {
            return result("Unavailable", reason = "Unverified app_zygote parent identity or context.\n$raw")
        }
        val nativeVerdict = lines.singleOrNull { it.startsWith("fd_reuse_verdict=") }
            ?.substringAfter("fd_reuse_verdict=")?.substringBefore(' ')
        if (nativeVerdict == "UNAVAILABLE") {
            return result("Unavailable", reason = raw)
        }
        val cases = readCases(raw) ?: return result("Inconclusive", reason = "Malformed/duplicate native write records.\n$raw")
        val validSize = carrier.toByteArray(Charsets.UTF_8).size
        val controlsPassed = lines.count { it == "fd_reuse_preflight=PASS" } == 1 &&
            cases["preflight_valid_valid"]?.isSequence(validSize, 0, -1, EBUSY) == true &&
            cases["preflight_invalid_invalid"]?.isSequence(-1, EINVAL, -1, EBUSY) == true &&
            cases["invalid_to_valid"]?.isSequence(-1, EINVAL, -1, EBUSY) == true
        if (!controlsPassed) {
            return result("Inconclusive", reason = "SELinuxFS transaction controls did not match stock semantics.\n$raw")
        }

        fun earlyReturn(prefix: String): Boolean =
            cases["${prefix}_to_valid"]?.isSequence(-1, EINVAL, validSize, 0) == true &&
                cases["${prefix}_to_invalid"]?.isSequence(-1, EINVAL, -1, EINVAL) == true

        fun noBypass(prefix: String, firstBytes: Int): Boolean {
            val valid = cases["${prefix}_to_valid"] ?: return false
            val invalid = cases["${prefix}_to_invalid"] ?: return false
            return (
                valid.isSequence(-1, EINVAL, -1, EBUSY) &&
                    invalid.isSequence(-1, EINVAL, -1, EBUSY)
                ) || (
                valid.isSequence(firstBytes, 0, -1, EBUSY) &&
                    invalid.isSequence(firstBytes, 0, -1, EBUSY)
                )
        }

        val xxksuEarly = earlyReturn("xxksu")
        val fileEarly = earlyReturn("xxksu_file")
        val xxksuNormal = noBypass("xxksu", 10)
        val fileNormal = noBypass("xxksu_file", 22)
        // Match the native any-candidate contract. A complete, controlled
        // early return is a strong signal on its own; another candidate's
        // unknown errno must not veto an already established positive.
        val detected = xxksuEarly || fileEarly
        val stockLike = xxksuNormal && fileNormal
        val resolvedVerdict = when {
            detected -> "EARLY_RETURN_CANDIDATE"
            stockLike -> "NO_BYPASS_OBSERVED"
            else -> "INCONCLUSIVE"
        }
        val records = buildString {
            append("App Zygote PID=$pid UID=$uid context=$carrier. ")
            append("Native verdict=$nativeVerdict; verified verdict=$resolvedVerdict. ")
            append("Preflight: valid→valid, invalid→invalid, invalid→valid all consumed their FD.")
            appendLine()
            for (name in listOf("xxksu_to_valid", "xxksu_to_invalid", "xxksu_file_to_valid", "xxksu_file_to_invalid")) {
                appendLine("$name: ${cases[name]?.describe() ?: "missing"}")
            }
            if (nativeVerdict != resolvedVerdict) {
                appendLine("Native summary differs from the verified raw write records; " +
                    "the per-write errno and controls take precedence.")
            }
            when {
                detected -> append(
                    "A complete same-FD early-return signature was observed for at least one " +
                        "xxksu-specific context. This is a strong, implementation-specific " +
                        "transaction-state anomaly, not universal proof of root.",
                )
                stockLike -> append(
                    "No same-FD early-return signature was observed; both candidate contexts " +
                        "consumed their transaction FD. This does not exclude xxksu or root.",
                )
                else -> append(
                    "No complete early-return signature was established. One or more candidate " +
                        "responses were unexpected; the result does not establish absence or presence of xxksu.",
                )
            }
        }
        return when {
            detected ->
                result("Early return observed (${listOfNotNull(
                    "xxksu".takeIf { xxksuEarly }, "xxksu_file".takeIf { fileEarly },
                ).joinToString(" + ")})", true, records)
            stockLike ->
                result("No FD bypass observed", false, records)
            else -> result("Inconclusive", reason = records)
        }
    }
}
