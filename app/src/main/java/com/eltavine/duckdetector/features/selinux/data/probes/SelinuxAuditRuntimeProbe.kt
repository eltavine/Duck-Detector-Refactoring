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

import com.eltavine.duckdetector.features.selinux.data.native.SelinuxNativeAuditBridge
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence

data class SelinuxAuditRuntimeProbeResult(
    val logcatChecked: Boolean,
    val hits: List<SelinuxAuditEvidence>,
    val sideChannelHits: List<SelinuxAuditEvidence>,
    val suspiciousActorHits: List<SelinuxAuditEvidence>,
    val failureReason: String?,
    val directProbeUsed: Boolean,
)

class SelinuxAuditRuntimeProbe(
    private val nativeBridge: SelinuxNativeAuditBridge = SelinuxNativeAuditBridge(),
    private val logcatReader: SelinuxAuditLogcatReader = SelinuxAuditLogcatReader(),
    private val auditAvcSideChannelProbe: AuditAvcSideChannelProbe = AuditAvcSideChannelProbe(),
) {

    fun inspect(): SelinuxAuditRuntimeProbeResult {
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val directProbeUsed = nativeSnapshot.callbackInstalled && nativeSnapshot.probeRan
        val referenceSignatures = nativeSnapshot.callbackLines
            .mapNotNull(auditAvcSideChannelProbe::parseCanonicalSignature)
            .distinct()
        val logcatRead = logcatReader.readRecentAuditLogs()
        val runtimeHits = buildRuntimeHits(
            output = logcatRead.output,
            probeMarker = nativeSnapshot.probeMarker,
            referenceSignatures = referenceSignatures,
            allowObserved = nativeSnapshot.allowObserved,
        )
        val sideChannelHits = when {
            !logcatRead.checked || logcatRead.output.isBlank() -> emptyList()
            !nativeSnapshot.probeMarker.isNullOrBlank() && referenceSignatures.isNotEmpty() -> {
                auditAvcSideChannelProbe.evaluateAgainstReferences(
                    output = logcatRead.output.lineSequence()
                        .map { it.trim() }
                        .filter { it.contains(nativeSnapshot.probeMarker) }
                        .joinToString("\n"),
                    references = referenceSignatures,
                ).hits
            }

            else -> emptyList()
        }
        val suspiciousActorHits = if (logcatRead.checked) {
            auditAvcSideChannelProbe.evaluateSuspiciousActors(logcatRead.output).hits
        } else {
            emptyList()
        }

        val failureReason = when {
            logcatRead.checked -> null
            directProbeUsed && !logcatRead.failureReason.isNullOrBlank() ->
                "${logcatRead.failureReason} Direct libselinux callback capture still worked in-process."

            !nativeSnapshot.failureReason.isNullOrBlank() -> nativeSnapshot.failureReason
            else -> logcatRead.failureReason
        }

        return SelinuxAuditRuntimeProbeResult(
            logcatChecked = logcatRead.checked,
            hits = runtimeHits,
            sideChannelHits = sideChannelHits,
            suspiciousActorHits = suspiciousActorHits,
            failureReason = failureReason,
            directProbeUsed = directProbeUsed,
        )
    }

    internal fun buildRuntimeHits(
        output: String,
        probeMarker: String?,
        referenceSignatures: List<AuditAvcSignature>,
        allowObserved: Boolean,
    ): List<SelinuxAuditEvidence> {
        val hits = mutableListOf<SelinuxAuditEvidence>()
        if (allowObserved) {
            hits += SelinuxAuditEvidence(
                label = "Unexpected allow",
                value = "selinux_check_access",
                detail = "Controlled deny probes returned allow for the current app context.",
                strongSignal = true,
            )
        }
        if (output.isBlank()) {
            return hits
        }

        val lines = output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toList()

        lines.firstOrNull { it.contains(AUDITPATCH_LOG_TAG, ignoreCase = true) }?.let { line ->
            hits += SelinuxAuditEvidence(
                label = "Log tag",
                value = AUDITPATCH_LOG_TAG,
                detail = line.trimToPreview(),
                strongSignal = true,
            )
        }
        correlationMismatch(lines, referenceSignatures, probeMarker)?.let { hit ->
            hits += hit
        }
        lines.firstOrNull {
            it.contains(AUDITPATCH_LIBRARY_NAME, ignoreCase = true) ||
                    it.contains(AUDITPATCH_HOOK_MARKER, ignoreCase = true)
        }?.let { line ->
            hits += SelinuxAuditEvidence(
                label = "Native hook",
                value = AUDITPATCH_LIBRARY_NAME,
                detail = line.trimToPreview(),
                strongSignal = true,
            )
        }
        return hits
    }

    private fun correlationMismatch(
        lines: List<String>,
        referenceSignatures: List<AuditAvcSignature>,
        probeMarker: String?,
    ): SelinuxAuditEvidence? {
        if (referenceSignatures.isEmpty() || probeMarker.isNullOrBlank()) {
            return lines.firstOrNull {
                it.contains(AUDITPATCH_FAKE_TCONTEXT, ignoreCase = true) &&
                        (it.contains("avc:", ignoreCase = true) || it.contains(
                            "audit",
                            ignoreCase = true
                        ))
            }?.let { line ->
                SelinuxAuditEvidence(
                    label = "Fake tcontext",
                    value = "priv_app alias",
                    detail = line.trimToPreview(),
                    strongSignal = true,
                )
            }
        }

        val referenceByKey = referenceSignatures.associateBy { it.matchKey() }
        return lines.firstNotNullOfOrNull { line ->
            if (!line.contains(probeMarker)) {
                return@firstNotNullOfOrNull null
            }
            val signature = auditAvcSideChannelProbe.parseCanonicalSignature(line)
                ?: return@firstNotNullOfOrNull null
            val expected = referenceByKey[signature.matchKey()] ?: return@firstNotNullOfOrNull null
            if (signature == expected) {
                return@firstNotNullOfOrNull null
            }
            val label =
                if (signature.tcontext.equals(AUDITPATCH_FAKE_TCONTEXT, ignoreCase = true)) {
                    "Fake tcontext"
                } else {
                    "Tcontext mismatch"
                }
            SelinuxAuditEvidence(
                label = label,
                value = "expected ${expected.tcontext}",
                detail = line.trimToPreview(),
                strongSignal = true,
            )
        }
    }

    private fun AuditAvcSignature.matchKey(): String {
        return listOf(
            permission.lowercase(),
            scontext.lowercase(),
            tclass.lowercase()
        ).joinToString("|")
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
        private const val AUDITPATCH_LOG_TAG = "zn-auditpatch"
        private const val AUDITPATCH_LIBRARY_NAME = "libauditpatch.so"
        private const val AUDITPATCH_HOOK_MARKER = "logd PLT hook success"
        private const val AUDITPATCH_FAKE_TCONTEXT = "u:r:priv_app:s0:c512,c768"
    }
}
