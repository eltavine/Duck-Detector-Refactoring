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

package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle

/**
 * A valid current /context label followed by an embedded NUL must be parsed
 * as the same context. The tested Hide scanner instead searches past the NUL.
 * The observation is correlated with the /access ignored-tail probe.
 */
internal object XxksuContextNulProbe {
    private const val ROUNDS = 4
    private const val EINVAL = 22
    private val names = listOf(
        "context_base", "context_nul_inv", "context_nul_ksu",
        "context_nul_inv_file", "context_nul_ksu_file", "context_nul_ksu_partial",
    )
    private val record = Regex(
        """^context_nul_case=(\w+) round=(\d+) size=(\d+) open_errno=(\d+) """ +
            """write_ret=(-?\d+) write_errno=(\d+) read_ret=(-?\d+) read_errno=(\d+) response=\[([^\[\]\r\n]*)]$""",
    )
    private val parent = Regex(
        """^access_tail_pid=(\d+) uid=(\d+) carrier=(\S+) enforcing=([01]) seccomp=(\d+)$""",
    )
    private val appZygote = Regex("""u:r:app_zygote:s0(?::c[0-9]+(?:,c[0-9]+)*)?""")

    private data class Sample(
        val length: Int, val openErrno: Int, val written: Int, val writeErrno: Int,
        val received: Int, val readErrno: Int, val response: String,
    ) {
        fun success(length: Int, expected: String): Boolean =
            this.length == length && openErrno == 0 && written == length &&
                writeErrno == 0 && readErrno == 0 &&
                received in expected.length..(expected.length + 2) &&
                response == expected

        fun rejected(length: Int): Boolean =
            this.length == length && openErrno == 0 && written == -1 &&
                writeErrno == EINVAL && received == -1 && readErrno == 0 &&
                response.isEmpty()

        val denied: Boolean get() =
            openErrno == 1 || openErrno == 13 || writeErrno == 1 || writeErrno == 13
    }

    private fun result(
        status: String, details: String, positive: Boolean = false, denied: Boolean = false,
    ) = SelinuxCheckResult(
        method = SelinuxOracle.XXKSU_CONTEXT_NUL.label,
        oracle = SelinuxOracle.XXKSU_CONTEXT_NUL,
        status = status,
        isSecure = if (positive) false else null,
        permissionDenied = denied,
        details = details,
    )

    fun interpret(raw: String?): SelinuxCheckResult {
        if (raw.isNullOrBlank()) return result("Unavailable", "No App Zygote /context NUL-tail record.")
        if (raw.length > 18_000) return result("Inconclusive", "Oversized SELinuxFS NUL-tail report.")
        val lines = raw.lineSequence().toList()
        // Older carriers contain /access observations but no /context sub-experiment.
        if (lines.none { it.startsWith("context_nul_case=") } &&
            lines.none { it.startsWith("context_nul_status=") }
        ) return result("Unavailable", "The carrier did not collect /context NUL-tail observations.")
        val identity = lines.singleOrNull { it.startsWith("access_tail_pid=") }
            ?.let(parent::matchEntire)
            ?: return result("Unavailable", "Unverified App Zygote parent identity.")
        val carrier = identity.groupValues[3]
        if (identity.groupValues[1].toIntOrNull()?.let { it > 0 } != true ||
            identity.groupValues[2].toIntOrNull()?.let { it >= 10000 } != true ||
            !appZygote.matches(carrier) || identity.groupValues[4] != "1" ||
            identity.groupValues[5] != "2"
        ) return result("Unavailable", "App Zygote, UID, enforcing or seccomp gate failed.")
        if (lines.count { it == "context_nul_prefix=$carrier" } != 1 ||
            lines.count { it == "context_nul_status=complete" } != 1 ||
            lines.count { it == "access_tail_status=complete identity_unchanged=true" } != 1
        ) return result("Inconclusive", "Incomplete /context NUL-tail collection or changed identity.")

        val suffixes = mapOf(
            "context_base" to "",
            "context_nul_inv" to "\u0000 :inv:",
            "context_nul_ksu" to "\u0000 :ksu:",
            "context_nul_inv_file" to "\u0000 :inv_file:",
            "context_nul_ksu_file" to "\u0000 :ksu_file:",
            "context_nul_ksu_partial" to "\u0000 :ksuX",
        )
        val sizes = suffixes.mapValues { (_, suffix) ->
            (carrier + suffix).toByteArray(Charsets.UTF_8).size
        }
        if (sizes["context_nul_inv"] != sizes["context_nul_ksu"] ||
            sizes["context_nul_inv_file"] != sizes["context_nul_ksu_file"]
        ) return result("Inconclusive", "Hidden NUL tails and placebos have different lengths.")

        val samples = mutableMapOf<Pair<Int, String>, Sample>()
        for (line in lines.filter { it.startsWith("context_nul_case=") }) {
            val groups = record.matchEntire(line)?.groupValues
                ?: return result("Inconclusive", "Malformed /context record: $line")
            val name = groups[1]
            val round = groups[2].toIntOrNull()
            val values = (3..8).map { groups[it].toIntOrNull() }
            if (name !in names || round == null || round !in 0 until ROUNDS ||
                values.any { it == null }
            ) return result("Inconclusive", "Unknown NUL-tail case, round or result.")
            val v = values.map { it!! }
            if (samples.put(round to name,
                    Sample(v[0], v[1], v[2], v[3], v[4], v[5], groups[9])) != null
            ) return result("Inconclusive", "Duplicate /context NUL-tail record.")
        }
        if (samples.size != ROUNDS * names.size)
            return result("Inconclusive", "Missing NUL-tail records: ${samples.size}/${ROUNDS * names.size}.")
        if (samples.values.any { it.denied })
            return result("Permission limited", "App Zygote /context open/write denied.",
                denied = true)

        val baseline = samples[0 to "context_base"]?.response
        if (baseline != carrier)
            return result("Inconclusive", "Baseline /context response is not the current carrier label.")
        val controls = listOf(
            "context_base", "context_nul_inv", "context_nul_inv_file", "context_nul_ksu_partial",
        )
        for (round in 0 until ROUNDS) {
            for (name in controls) {
                if (samples[round to name]?.success(sizes.getValue(name), carrier) != true)
                    return result("Inconclusive",
                        "Ordinary /context NUL control or canonical response failed: $name round=$round.")
            }
        }
        val hidden = listOf("context_nul_ksu", "context_nul_ksu_file")
        val rejected = (0 until ROUNDS).all { round ->
            hidden.all { samples[round to it]?.rejected(sizes.getValue(it)) == true }
        }
        val accepted = (0 until ROUNDS).all { round ->
            hidden.all { samples[round to it]?.success(sizes.getValue(it), carrier) == true }
        }
        val details = "App Zygote context=$carrier, enforcing=1 seccomp=2. " +
            "Four rounds using the same valid context before the first NUL. " +
            "Base, equal-length :inv:/:inv_file: placebos and :ksuX all returned " +
            "the same canonical context. " +
            hidden.joinToString(" ") { name ->
                name + "=" + (0 until ROUNDS).joinToString("/") { round ->
                    samples.getValue(round to name).let { "${it.written}:errno=${it.writeErrno}" }
                }
            } + ". "
        return when {
            rejected -> result("NUL-tail rejection observed",
                details + "Only hidden-type bytes beyond the first NUL returned EINVAL. " +
                    "This parser/scanner mismatch shares the same Hide mechanism as /access; " +
                    "it is not independent or universal proof of root.", positive = true)
            accepted -> result("No NUL-tail rejection observed",
                details + "Both hidden tails succeeded; absence does not exclude SELinux Hide.")
            else -> result("Inconclusive",
                details + "Mixed or unexpected hidden-tail results cannot prove a scanner mismatch.")
        }
    }
}
