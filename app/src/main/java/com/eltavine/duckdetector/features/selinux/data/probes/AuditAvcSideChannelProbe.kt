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

import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence

internal data class AuditAvcSignature(
    val permission: String,
    val scontext: String,
    val tcontext: String,
    val tclass: String,
)

internal data class AuditAvcRecord(
    val line: String,
    val signature: AuditAvcSignature,
    val comm: String? = null,
    val exe: String? = null,
    val path: String? = null,
    val name: String? = null,
)

data class AuditAvcSideChannelProbeResult(
    val hits: List<SelinuxAuditEvidence>,
)

class AuditAvcSideChannelProbe {

    fun evaluate(
        output: String,
    ): AuditAvcSideChannelProbeResult {
        if (output.isBlank()) {
            return AuditAvcSideChannelProbeResult(hits = emptyList())
        }

        val hits = output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .filter(::looksLikeForeignAvcLeak)
            .distinct()
            .take(MAX_HITS)
            .map { line ->
                SelinuxAuditEvidence(
                    label = "AVC denial leak",
                    value = extractValue(line),
                    detail = line.trimToPreview(),
                    strongSignal = false,
                )
            }
            .toList()

        return AuditAvcSideChannelProbeResult(hits = hits)
    }

    internal fun evaluateAgainstReferences(
        output: String,
        references: List<AuditAvcSignature>,
    ): AuditAvcSideChannelProbeResult {
        if (output.isBlank() || references.isEmpty()) {
            return AuditAvcSideChannelProbeResult(hits = emptyList())
        }

        val referenceSet = references.toSet()
        val hits = output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .filter { line ->
                parseCanonicalSignature(line) in referenceSet
            }
            .distinct()
            .take(MAX_HITS)
            .map { line ->
                SelinuxAuditEvidence(
                    label = "AVC denial leak",
                    value = extractValue(line),
                    detail = line.trimToPreview(),
                    strongSignal = false,
                )
            }
            .toList()

        return AuditAvcSideChannelProbeResult(hits = hits)
    }

    internal fun parseCanonicalSignature(
        line: String,
    ): AuditAvcSignature? {
        return parseCanonicalRecord(line)?.signature
    }

    internal fun evaluateSuspiciousActors(
        output: String,
    ): AuditAvcSideChannelProbeResult {
        if (output.isBlank()) {
            return AuditAvcSideChannelProbeResult(hits = emptyList())
        }

        val hits = output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .mapNotNull(::parseCanonicalRecord)
            .filter(::looksLikeForeignAvcLeak)
            .filter(::hasSuspiciousActor)
            .distinctBy { it.line }
            .take(MAX_HITS)
            .map { record ->
                SelinuxAuditEvidence(
                    label = "su-related AVC",
                    value = suspiciousActorValue(record),
                    detail = record.line.trimToPreview(),
                    strongSignal = false,
                )
            }
            .toList()

        return AuditAvcSideChannelProbeResult(hits = hits)
    }

    internal fun parseCanonicalRecord(
        line: String,
    ): AuditAvcRecord? {
        val normalized = line.lowercase()
        if ("type=1400" !in normalized || "avc:" !in normalized || "denied" !in normalized) {
            return null
        }
        if (
            "audit(" !in normalized ||
            "scontext=" !in normalized ||
            "tcontext=" !in normalized ||
            "tclass=" !in normalized
        ) {
            return null
        }

        val permission = extractGroup(line, PERMISSION_REGEX) ?: return null
        val scontext = extractGroup(line, SCONTEXT_REGEX) ?: return null
        val tcontext = extractGroup(line, TCONTEXT_REGEX) ?: return null
        val tclass = extractGroup(line, TCLASS_REGEX) ?: return null
        return AuditAvcRecord(
            line = line,
            signature = AuditAvcSignature(
                permission = permission.trim(),
                scontext = scontext,
                tcontext = tcontext,
                tclass = tclass,
            ),
            comm = extractGroup(line, COMM_REGEX),
            exe = extractFieldValue(line, "exe"),
            path = extractFieldValue(line, "path"),
            name = extractFieldValue(line, "name"),
        )
    }

    private fun looksLikeForeignAvcLeak(
        line: String,
    ): Boolean {
        if (parseCanonicalSignature(line) == null) {
            return false
        }
        val normalized = line.lowercase()
        if (
            normalized.contains("zn-auditpatch") ||
            normalized.contains("libauditpatch.so") ||
            normalized.contains("logd plt hook success")
        ) {
            return false
        }
        return true
    }

    private fun looksLikeForeignAvcLeak(
        record: AuditAvcRecord,
    ): Boolean = looksLikeForeignAvcLeak(record.line)

    private fun hasSuspiciousActor(
        record: AuditAvcRecord,
    ): Boolean {
        val normalizedComm = record.comm?.trim()?.lowercase()
        if (normalizedComm != null && normalizedComm in SUSPICIOUS_COMM_VALUES) {
            return true
        }

        return listOfNotNull(record.exe, record.path, record.name)
            .map { it.lowercase() }
            .any { value ->
                SUSPICIOUS_PATH_TOKENS.any { token -> token in value }
            }
    }

    private fun suspiciousActorValue(
        record: AuditAvcRecord,
    ): String {
        record.comm?.takeIf { it.isNotBlank() }?.let { return "comm=$it" }
        record.exe?.takeIf { it.isNotBlank() }?.let { return "exe=$it" }
        record.path?.takeIf { it.isNotBlank() }?.let { return "path=$it" }
        record.name?.takeIf { it.isNotBlank() }?.let { return "name=$it" }
        return "Root-like actor"
    }

    private fun extractValue(
        line: String,
    ): String {
        extractGroup(line, COMM_REGEX)?.let { return "comm=$it" }
        extractGroup(line, SCONTEXT_REGEX)?.let { return "scontext=$it" }
        extractGroup(line, TCONTEXT_REGEX)?.let { return "tcontext=$it" }
        return "Readable"
    }

    private fun extractGroup(
        line: String,
        regex: Regex,
    ): String? = regex.find(line)?.groupValues?.getOrNull(1)

    private fun extractFieldValue(
        line: String,
        field: String,
    ): String? {
        val escapedField = Regex.escape(field)
        val quoted = Regex("$escapedField=\"([^\"]+)\"", RegexOption.IGNORE_CASE)
        extractGroup(line, quoted)?.let { return it }
        val plain = Regex("$escapedField=([^\\s]+)", RegexOption.IGNORE_CASE)
        return extractGroup(line, plain)
    }

    private fun String.trimToPreview(
        maxLength: Int = 180,
    ): String {
        val normalized = replace(Regex("\\s+"), " ").trim()
        return if (normalized.length <= maxLength) {
            normalized
        } else {
            normalized.take(maxLength - 3).trimEnd() + "..."
        }
    }

    private companion object {
        private const val MAX_HITS = 3
        private val PERMISSION_REGEX =
            Regex("""avc:\s*denied\s*\{\s*([^}]+)\s*\}""", RegexOption.IGNORE_CASE)
        private val COMM_REGEX = Regex("comm=\"([^\"]+)\"", RegexOption.IGNORE_CASE)
        private val SCONTEXT_REGEX = Regex("""scontext=([^\s]+)""", RegexOption.IGNORE_CASE)
        private val TCONTEXT_REGEX = Regex("""tcontext=([^\s]+)""", RegexOption.IGNORE_CASE)
        private val TCLASS_REGEX = Regex("""tclass=([^\s]+)""", RegexOption.IGNORE_CASE)
        private val SUSPICIOUS_COMM_VALUES = setOf(
            "su",
            "magisk",
            "magiskd",
            "ksud",
            "kernelsu",
            "apatch",
            "apd",
        )
        private val SUSPICIOUS_PATH_TOKENS = setOf(
            "/su",
            "/magisk",
            "magiskd",
            "ksud",
            "kernelsu",
            "apatch",
            "/data/adb",
        )
    }
}
