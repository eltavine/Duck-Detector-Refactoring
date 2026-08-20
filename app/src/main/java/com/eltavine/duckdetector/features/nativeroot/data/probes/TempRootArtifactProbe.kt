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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit

data class TempRootArtifactProbeResult(
    val available: Boolean,
    val checkedCount: Int,
    val findings: List<NativeRootFinding>,
    val tempRootDetected: Boolean,
    val cveExploitDetected: Boolean,
    val detail: String,
) {
    val hitCount: Int
        get() = findings.size
}

/**
 * Scans /data/local/tmp for file artifacts associated with temporary root exploits
 * (ksud, temp_su, ksu-helper, ksu-payload, libcve43499root.so).
 * When any filename contains "cve43499" or "cve-2026-43499" (case-insensitive),
 * the probe flags an active CVE-2026-43499 temp root exploit.
 *
 * Because /data/local/tmp is typically owned by shell:shell with mode drwxrwx--x,
 * apps cannot enumerate the directory (listFiles returns null). The probe uses a
 * three-phase strategy:
 * 1. Try File.listFiles() (works on permissive SELinux or if app has shell GID).
 * 2. Try "ls /data/local/tmp" via ProcessBuilder (works if the app can exec ls with
 *    inherited permissions).
 * 3. Fall back to probing known artifact filenames via File.exists(), which succeeds
 *    because the directory has execute (traverse) permission for others.
 */
class TempRootArtifactProbe {

    fun run(): TempRootArtifactProbeResult {
        val tmpDir = File(TMP_PATH)

        // Phase 1: Direct listing via Java File API
        val entries = try {
            tmpDir.listFiles()?.toList()
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        }

        if (entries != null) {
            return evaluate(entries.map { it.name })
        }

        // Phase 2: Try listing via ProcessBuilder("ls", path)
        val lsEntries = execListing(TMP_PATH)
        if (lsEntries.isNotEmpty()) {
            return evaluate(lsEntries)
        }

        // Phase 3: Probe known filenames individually using File.exists()
        // The directory has --x for others, so stat on known paths works.
        return probeKnownFiles()
    }

    internal fun evaluate(fileNames: List<String>): TempRootArtifactProbeResult {
        val findings = mutableListOf<NativeRootFinding>()
        var cveExploitDetected = false

        fileNames.forEach { name ->
            val lowerName = name.lowercase()
            val isCveExploit = lowerName.contains(CVE_ID_SHORT) ||
                    lowerName.contains(CVE_ID_FULL)
            val isKnownArtifact = KNOWN_ARTIFACT_PREFIXES.any { prefix ->
                lowerName.startsWith(prefix)
            } || KNOWN_ARTIFACT_EXACT.any { exact ->
                lowerName == exact
            }

            if (isCveExploit) {
                cveExploitDetected = true
                findings += NativeRootFinding(
                    id = "temp_root_cve_${findings.size}",
                    label = "Temp root CVE exploit artifact",
                    value = name,
                    detail = "File \"$name\" in $TMP_PATH matches CVE-2026-43499 temp root exploit pattern. This indicates an active or recent temporary root escalation.",
                    group = NativeRootGroup.PATH,
                    severity = NativeRootFindingSeverity.DANGER,
                    detailMonospace = true,
                )
            } else if (isKnownArtifact) {
                findings += NativeRootFinding(
                    id = "temp_root_artifact_${findings.size}",
                    label = "Temp root artifact",
                    value = name,
                    detail = "File \"$name\" in $TMP_PATH is a known temporary root infrastructure artifact (ksud/temp_su/ksu-helper/ksu-payload).",
                    group = NativeRootGroup.PATH,
                    severity = NativeRootFindingSeverity.DANGER,
                    detailMonospace = true,
                )
            }
        }

        val tempRootDetected = findings.isNotEmpty()

        return TempRootArtifactProbeResult(
            available = true,
            checkedCount = fileNames.size,
            findings = findings,
            tempRootDetected = tempRootDetected,
            cveExploitDetected = cveExploitDetected,
            detail = if (tempRootDetected) {
                "${findings.size} temp root artifact(s) found in $TMP_PATH."
            } else {
                "No temp root artifacts in $TMP_PATH (${fileNames.size} entries scanned)."
            },
        )
    }

    /**
     * Probes known artifact filenames individually via File.exists().
     * This works on directories with execute-only (traverse) permission for others,
     * where listing is denied but stat on known paths succeeds.
     */
    private fun probeKnownFiles(): TempRootArtifactProbeResult {
        val foundNames = mutableListOf<String>()
        KNOWN_PROBE_FILENAMES.forEach { filename ->
            try {
                if (File(TMP_PATH, filename).exists()) {
                    foundNames += filename
                }
            } catch (_: SecurityException) {
                // SELinux or other MAC may block stat; skip this entry
            }
        }

        if (foundNames.isEmpty()) {
            return TempRootArtifactProbeResult(
                available = true,
                checkedCount = KNOWN_PROBE_FILENAMES.size,
                findings = emptyList(),
                tempRootDetected = false,
                cveExploitDetected = false,
                detail = "Probed ${KNOWN_PROBE_FILENAMES.size} known paths in $TMP_PATH; none found.",
            )
        }

        return evaluate(foundNames)
    }

    /**
     * Attempts to list the directory via ProcessBuilder("ls", path).
     * Returns the list of filenames or empty if listing fails.
     */
    private fun execListing(path: String): List<String> {
        var process: Process? = null
        return try {
            process = ProcessBuilder("ls", path)
                .redirectErrorStream(true)
                .start()
            val lines = process.inputStream.bufferedReader().useLines { seq ->
                seq.filter { it.isNotBlank() && it != "." && it != ".." }
                    .map { it.trim() }
                    .toList()
            }
            if (!process.waitFor(LS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return emptyList()
            }
            if (process.exitValue() != 0) emptyList() else lines
        } catch (_: Exception) {
            emptyList()
        } finally {
            process?.destroy()
        }
    }

    private companion object {
        private const val TMP_PATH = "/data/local/tmp"
        private const val CVE_ID_SHORT = "cve43499"
        private const val CVE_ID_FULL = "cve-2026-43499"
        private const val LS_TIMEOUT_SECONDS = 3L

        // Prefix-matched: catches ksud-aarch64-linux-android, ksud-s25u-kdp, temp_su.sock, etc.
        private val KNOWN_ARTIFACT_PREFIXES = listOf(
            "ksud",
            "temp_su",
        )

        // Exact-matched (lowercase)
        private val KNOWN_ARTIFACT_EXACT = listOf(
            "ksu-helper",
            "ksu-payload",
        )

        /**
         * Known filenames to probe individually via File.exists() when directory listing
         * is denied. This covers common ksud build variants, temp_su socket, ksu-helper,
         * ksu-payload, and the CVE exploit library.
         */
        private val KNOWN_PROBE_FILENAMES = listOf(
            // ksud binary variants (arch + device-specific)
            "ksud",
            "ksud-aarch64-linux-android",
            "ksud-arm-linux-androideabi",
            "ksud-x86_64-linux-android",
            "ksud-i686-linux-android",
            "ksud-s25u-kdp",
            "ksud-s25-kdp",
            "ksud-s24u-kdp",
            "ksud-s24-kdp",
            "ksud-pixel9-kdp",
            "ksud-pixel8-kdp",
            "ksud-nothing2-kdp",
            // temp_su socket/binary
            "temp_su",
            "temp_su.sock",
            "temp_su.socket",
            // ksu utilities
            "ksu-helper",
            "ksu-payload",
            // CVE-2026-43499 exploit artifacts
            "libcve43499root.so",
            "cve43499",
            "cve-2026-43499",
            "cve43499.sh",
            "cve-2026-43499.sh",
        )
    }
}
