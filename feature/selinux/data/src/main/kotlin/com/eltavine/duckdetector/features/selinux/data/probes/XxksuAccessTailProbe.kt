/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */
package com.eltavine.duckdetector.features.selinux.data.probes

import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle

/**
 * SELinuxFS /access: normal parser ignores the fourth field, but a Hide
 * scanner may inspect its bytes. A distinct mechanism from same-FD bypass.
 * Parse the complete raw record; no native summary can itself imply Danger.
 */
internal object XxksuAccessTailProbe {
    private const val ROUNDS = 4
    private const val EINVAL = 22
    private val names = setOf(
        "base", "tail_inv", "tail_ksu", "tail_inv_file", "tail_ksu_file",
        "tail_ksu_partial", "invalid_source",
    )
    private val recordPattern = Regex(
        """^access_tail_case=(\w+) round=(\d+) size=(\d+) open_errno=(\d+) """ +
            """write_ret=(-?\d+) write_errno=(\d+) read_ret=(-?\d+) read_errno=(\d+) response=\[([^\[\]\r\n]*)]$""",
    )
    private val parent = Regex(
        """^access_tail_pid=(\d+) uid=(\d+) carrier=(\S+) enforcing=([01]) seccomp=(\d+)$""",
    )
    private val expectedCarrier = Regex("""u:r:app_zygote:s0(?::c[0-9]+(?:,c[0-9]+)*)?""")
    private val sixFields = Regex("""(?:0[xX])?[0-9a-fA-F]+""")

    private data class Sample(
        val bytes: Int,
        val openError: Int,
        val written: Int,
        val writeError: Int,
        val received: Int,
        val readError: Int,
        val response: String,
    ) {
        fun success(expected: Int, canonical: String): Boolean =
            openError == 0 && bytes == expected && written == expected &&
                writeError == 0 && received in canonical.length..(canonical.length + 2) &&
                readError == 0 && response == canonical

        fun rejected(expected: Int): Boolean =
            openError == 0 && bytes == expected && written == -1 &&
                writeError == EINVAL && received == -1 && readError == 0 &&
                response.isEmpty()
    }

    private fun result(
        status: String, reason: String, hit: Boolean = false, denied: Boolean = false,
    ) = SelinuxCheckResult(
        method = SelinuxOracle.XXKSU_ACCESS_TAIL.label,
        oracle = SelinuxOracle.XXKSU_ACCESS_TAIL,
        status = status,
        isSecure = if (hit) false else null,
        permissionDenied = denied,
        details = reason,
    )

    fun interpret(raw: String?): SelinuxCheckResult {
        if (raw.isNullOrBlank()) return result("Unavailable", "No App Zygote parent /access ignored-tail result.")
        if (raw.length > 12_288) return result("Inconclusive", "Oversized native ignored-tail report.")
        val lines = raw.lineSequence().toList()
        val identity = lines.singleOrNull { it.startsWith("access_tail_pid=") }
            ?.let(parent::matchEntire)
            ?: return result("Unavailable", "Unverified App Zygote parent identity.\n" + raw)
        val pid = identity.groupValues[1].toIntOrNull()
        val uid = identity.groupValues[2].toIntOrNull()
        val carrier = identity.groupValues[3]
        if (pid == null || pid <= 0 || uid == null || uid < 10000 ||
            !expectedCarrier.matches(carrier) ||
            identity.groupValues[4] != "1" || identity.groupValues[5] != "2"
        ) return result("Unavailable", "App Zygote, enforcing or seccomp gate failed: " +
            "pid=" + pid + " uid=" + uid + " labelMatches=" + expectedCarrier.matches(carrier) +
            " enforcing=" + identity.groupValues[4] + " seccomp=" + identity.groupValues[5] +
            ".\n" + raw)
        if (lines.count { it == "access_tail_status=complete identity_unchanged=true" } != 1)
            return result("Inconclusive", "Incomplete experiment or changed process identity.\n" + raw)

        val prefix = lines.singleOrNull { it.startsWith("access_tail_prefix=") }
            ?.removePrefix("access_tail_prefix=")
            ?: return result("Inconclusive", "Missing frozen SELinuxFS access prefix.\n" + raw)
        val classId = prefix.removePrefix(carrier + " " + carrier + " ")
        if (classId == prefix || classId.toIntOrNull()?.let { it in 1..65535 } != true ||
            prefix != carrier + " " + carrier + " " + classId
        ) return result("Inconclusive", "Malformed or inconsistent self-access query prefix.\n" + raw)
        val suffixes = mapOf(
            "base" to "",
            "tail_inv" to " :inv:",
            "tail_ksu" to " :ksu:",
            "tail_inv_file" to " :inv_file:",
            "tail_ksu_file" to " :ksu_file:",
            "tail_ksu_partial" to " :ksuX",
        )
        val lengths = suffixes.mapValues { (prefix + it.value).toByteArray(Charsets.UTF_8).size } +
            ("invalid_source" to
                ("u:r:__access_tail_absent__:s0 " + carrier + " " + classId)
                    .toByteArray(Charsets.UTF_8).size)
        if (lengths["tail_ksu"] != lengths["tail_inv"] ||
            lengths["tail_ksu_file"] != lengths["tail_inv_file"]
        ) return result("Inconclusive", "Hidden tails and placebo lengths differ.")

        val samples = mutableMapOf<Pair<Int, String>, Sample>()
        for (line in lines.filter { it.startsWith("access_tail_case=") }) {
            val match = recordPattern.matchEntire(line)
                ?: return result("Inconclusive", "Malformed native /access record: " + line)
            val groups = match.groupValues
            val name = groups[1]
            val round = groups[2].toIntOrNull()
            val values = (3..8).map { groups[it].toIntOrNull() }
            if (name !in names || round == null || round !in 0 until ROUNDS ||
                values.any { it == null }
            ) return result("Inconclusive", "Unknown case, round or numeric record.")
            val v = values.map { it!! }
            if (samples.put(round to name, Sample(v[0], v[1], v[2], v[3], v[4], v[5], groups[9])) != null)
                return result("Inconclusive", "Duplicate /access record.")
        }
        if (samples.size != ROUNDS * names.size)
            return result("Inconclusive", "Missing /access records: " + samples.size + "/" + ROUNDS * names.size)
        if (samples.values.any { it.openError == 13 || it.openError == 1 ||
                it.writeError == 13 || it.writeError == 1
            }
        ) return result("Permission limited", "The App Zygote /access request was denied by a permission gate.",
            denied = true)

        val canonical = samples[0 to "base"]?.response.orEmpty()
        val tokens = canonical.trim().split(Regex("""\s+"""))
        if (tokens.size != 6 || tokens.any { !sixFields.matches(it) })
            return result("Inconclusive", "Baseline reply is not a six-field AV decision.")

        for (round in 0 until ROUNDS) {
            for (name in listOf("base", "tail_inv", "tail_inv_file", "tail_ksu_partial")) {
                if (samples[round to name]?.success(lengths.getValue(name), canonical) != true)
                    return result("Inconclusive",
                        "Ordinary /access control or reply equality failed: " + name +
                            " round=" + round + "\n" + raw)
            }
            if (samples[round to "invalid_source"]?.rejected(lengths.getValue("invalid_source")) != true)
                return result("Inconclusive", "Invalid source control did not return EINVAL.\n" + raw)
        }
        val hidden = listOf("tail_ksu", "tail_ksu_file")
        val allRejected = (0 until ROUNDS).all { round ->
            hidden.all { samples[round to it]?.rejected(lengths.getValue(it)) == true }
        }
        val allSucceeded = (0 until ROUNDS).all { round ->
            hidden.all { samples[round to it]?.success(lengths.getValue(it), canonical) == true }
        }
        val details = "App Zygote pid=" + pid + " uid=" + uid + " context=" + carrier +
            " enforcing=1 seccomp=2. Four rounds with the same source, target and class. " +
            "Base, equal-length :inv:/:inv_file: placebos and :ksuX all returned the same " +
            "six-field access response; invalid-source EINVAL verified. " +
            hidden.joinToString(" ") { name ->
                name + "=" + (0 until ROUNDS).joinToString("/") { round ->
                    val item = samples.getValue(round to name)
                    item.written.toString() + ":errno=" + item.writeError
                }
            } + ". "
        return when {
            allRejected -> result(
                "Ignored-tail rejection observed",
                details + "Both hidden-type tails returned EINVAL in every round while " +
                    "the parser-equivalent control tails succeeded. Implementation-specific " +
                    "parser/scanner mismatch, not universal Root proof. Shared mechanism " +
                    "with other SELinux Hide probes must not be counted as independent evidence.",
                hit = true,
            )
            allSucceeded -> result(
                "No ignored-tail rejection observed",
                details + "Both hidden suffixes were accepted. Absence does not exclude a hook.",
            )
            else -> result(
                "Inconclusive",
                details + "Mixed, missing or otherwise unexpected hidden-tail results.",
            )
        }
    }
}
