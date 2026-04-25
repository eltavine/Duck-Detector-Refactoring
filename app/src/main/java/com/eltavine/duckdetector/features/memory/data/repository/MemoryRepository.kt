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

package com.eltavine.duckdetector.features.memory.data.repository

import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeBridge
import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeFinding
import com.eltavine.duckdetector.features.memory.data.native.MemoryNativeSnapshot
import com.eltavine.duckdetector.features.memory.domain.MemoryFinding
import com.eltavine.duckdetector.features.memory.domain.MemoryFindingSection
import com.eltavine.duckdetector.features.memory.domain.MemoryFindingSeverity
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodOutcome
import com.eltavine.duckdetector.features.memory.domain.MemoryMethodResult
import com.eltavine.duckdetector.features.memory.domain.MemoryReport
import com.eltavine.duckdetector.features.memory.domain.MemoryStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class MemoryRepository(
    private val nativeBridge: MemoryNativeBridge = MemoryNativeBridge(),
) {

    suspend fun scan(): MemoryReport = withContext(Dispatchers.Default) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                MemoryReport.failed(throwable.message ?: "Memory scan failed.")
            }
    }

    private fun scanInternal(): MemoryReport {
        val snapshot = sanitizeSnapshot(nativeBridge.collectSnapshot())
        if (!snapshot.available) {
            return MemoryReport.failed("Native memory snapshot was unavailable.")
        }

        val findings = snapshot.findings.mapIndexed { index, finding ->
            MemoryFinding(
                id = "memory_$index",
                section = finding.section.toSection(),
                category = finding.category,
                label = finding.label.ifBlank { finding.category.prettyLabel() },
                detail = finding.detail,
                severity = finding.severity.toSeverity(),
                detailMonospace = finding.detail.shouldUseMonospace(),
            )
        }.sortedWith(
            compareBy<MemoryFinding> { severityPriority(it.severity) }
                .thenBy { sectionPriority(it.section) }
                .thenBy { it.label },
        )

        return MemoryReport(
            stage = MemoryStage.READY,
            nativeAvailable = true,
            findings = findings,
            methods = buildMethods(snapshot),
            modifiedFunctionCount = snapshot.modifiedFunctionCount,
            gotPltHook = snapshot.gotPltHook,
            inlineHook = snapshot.inlineHook,
            prologueModified = snapshot.prologueModified,
            trampoline = snapshot.trampoline,
            suspiciousJump = snapshot.suspiciousJump,
            writableExec = snapshot.writableExec,
            anonymousExec = snapshot.anonymousExec,
            swappedExec = snapshot.swappedExec,
            sharedDirtyExec = snapshot.sharedDirtyExec,
            deletedSo = snapshot.deletedSo,
            suspiciousMemfd = snapshot.suspiciousMemfd,
            execAshmem = snapshot.execAshmem,
            devZeroExec = snapshot.devZeroExec,
            signalHandler = snapshot.signalHandler,
            fridaSignal = snapshot.fridaSignal,
            anonymousSignal = snapshot.anonymousSignal,
            vdsoRemapped = snapshot.vdsoRemapped,
            vdsoUnusualBase = snapshot.vdsoUnusualBase,
            deletedLibrary = snapshot.deletedLibrary,
            hiddenModule = snapshot.hiddenModule,
            mapsOnlyModule = snapshot.mapsOnlyModule,
        )
    }

    internal fun buildMethods(snapshot: MemoryNativeSnapshot): List<MemoryMethodResult> {
        return listOf(
            MemoryMethodResult(
                label = "GOT/PLT resolution",
                summary = when {
                    snapshot.gotPltHook -> "Mismatch"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.gotPltHook -> MemoryMethodOutcome.DETECTED
                    else -> MemoryMethodOutcome.CLEAN
                },
                detail = "Checks whether critical libc and linker symbols still resolve into their expected native modules.",
            ),
            MemoryMethodResult(
                label = "Entry prologue",
                summary = when {
                    snapshot.inlineHook || snapshot.prologueModified -> "Hook-like"
                    snapshot.trampoline -> "Jump entry"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.inlineHook || snapshot.prologueModified -> MemoryMethodOutcome.DETECTED
                    snapshot.trampoline -> MemoryMethodOutcome.REVIEW
                    else -> MemoryMethodOutcome.CLEAN
                },
                detail = "Looks for branch-heavy entry bytes and trampoline-style handoff patterns at sensitive function starts.",
            ),
            MemoryMethodResult(
                label = "maps + smaps",
                summary = when {
                    snapshot.writableExec || snapshot.anonymousExec || snapshot.sharedDirtyExec -> "Anomaly"
                    snapshot.swappedExec -> "Review"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.writableExec || snapshot.anonymousExec || snapshot.sharedDirtyExec -> MemoryMethodOutcome.DETECTED
                    snapshot.swappedExec -> MemoryMethodOutcome.REVIEW
                    else -> MemoryMethodOutcome.CLEAN
                },
                detail = "Scans non-ART executable mappings for writable code, unexpected swapped pages, and shared-dirty system code.",
            ),
            MemoryMethodResult(
                label = "FD-backed code",
                summary = when {
                    snapshot.deletedSo || snapshot.suspiciousMemfd -> "Suspicious"
                    snapshot.execAshmem || snapshot.devZeroExec -> "Review"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.deletedSo || snapshot.suspiciousMemfd -> MemoryMethodOutcome.DETECTED
                    snapshot.execAshmem || snapshot.devZeroExec -> MemoryMethodOutcome.REVIEW
                    else -> MemoryMethodOutcome.CLEAN
                },
                detail = "Cross-checks executable mappings and live file descriptors for deleted libraries, memfd loaders, ashmem, and /dev/zero execution.",
            ),
            MemoryMethodResult(
                label = "Signal handlers",
                summary = when {
                    snapshot.fridaSignal || snapshot.anonymousSignal -> "Suspicious"
                    snapshot.signalHandler -> "Review"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.fridaSignal || snapshot.anonymousSignal -> MemoryMethodOutcome.DETECTED
                    snapshot.signalHandler -> MemoryMethodOutcome.REVIEW
                    else -> MemoryMethodOutcome.CLEAN
                },
                detail = "Enumerates SIGTRAP/SIGBUS/SIGSEGV/SIGILL handlers and checks whether they point into anonymous or loader-suspicious memory.",
            ),
            MemoryMethodResult(
                label = "Loader visibility",
                summary = when {
                    snapshot.hiddenModule || snapshot.deletedLibrary -> "Mismatch"
                    snapshot.mapsOnlyModule || snapshot.vdsoRemapped || snapshot.vdsoUnusualBase -> "Review"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.hiddenModule || snapshot.deletedLibrary -> MemoryMethodOutcome.DETECTED
                    snapshot.mapsOnlyModule || snapshot.vdsoRemapped || snapshot.vdsoUnusualBase -> MemoryMethodOutcome.REVIEW
                    else -> MemoryMethodOutcome.CLEAN
                },
                detail = "Compares /proc/self/maps against dl_iterate_phdr and sanity-checks the current process [vdso] view.",
            ),
        )
    }

    private fun String.toSection(): MemoryFindingSection {
        return when (uppercase()) {
            "HOOK" -> MemoryFindingSection.HOOK
            "MAPS" -> MemoryFindingSection.MAPS
            "FD" -> MemoryFindingSection.FD
            "SIGNAL" -> MemoryFindingSection.SIGNAL
            "VDSO" -> MemoryFindingSection.VDSO
            "LINKER" -> MemoryFindingSection.LINKER
            else -> MemoryFindingSection.MAPS
        }
    }

    private fun String.toSeverity(): MemoryFindingSeverity {
        return when (uppercase()) {
            "CRITICAL" -> MemoryFindingSeverity.CRITICAL
            "HIGH" -> MemoryFindingSeverity.HIGH
            "MEDIUM" -> MemoryFindingSeverity.MEDIUM
            else -> MemoryFindingSeverity.LOW
        }
    }

    private fun String.prettyLabel(): String {
        return lowercase().split('_').joinToString(" ") { token ->
            token.replaceFirstChar { it.uppercase() }
        }
    }

    internal fun sanitizeSnapshot(snapshot: MemoryNativeSnapshot): MemoryNativeSnapshot {
        if (!snapshot.available || snapshot.findings.isEmpty()) {
            return snapshot
        }

        val filteredFindings = snapshot.findings.filterNot(::isBenignArtCodeCacheSwapFinding)
        val hasSwappedExecFinding = filteredFindings.any { finding ->
            finding.section.equals("MAPS", ignoreCase = true) &&
                    finding.label == SWAPPED_EXEC_LABEL
        }
        return snapshot.copy(
            swappedExec = hasSwappedExecFinding,
            findings = filteredFindings,
        )
    }

    internal fun isBenignArtCodeCacheSwapFinding(finding: MemoryNativeFinding): Boolean {
        if (!finding.section.equals(
                "MAPS",
                ignoreCase = true
            ) || finding.label != SWAPPED_EXEC_LABEL
        ) {
            return false
        }
        val loweredDetail = finding.detail.lowercase()
        return BENIGN_ART_CODE_CACHE_MARKERS.any(loweredDetail::contains)
    }

    private fun String.shouldUseMonospace(): Boolean {
        return contains("0x") ||
                contains("/data/") ||
                contains("/proc/") ||
                contains(".so") ||
                contains("[vdso]") ||
                contains("memfd:")
    }

    private fun severityPriority(severity: MemoryFindingSeverity): Int {
        return when (severity) {
            MemoryFindingSeverity.CRITICAL -> 0
            MemoryFindingSeverity.HIGH -> 1
            MemoryFindingSeverity.MEDIUM -> 2
            MemoryFindingSeverity.LOW -> 3
        }
    }

    private fun sectionPriority(section: MemoryFindingSection): Int {
        return when (section) {
            MemoryFindingSection.HOOK -> 0
            MemoryFindingSection.MAPS -> 1
            MemoryFindingSection.FD -> 2
            MemoryFindingSection.SIGNAL -> 3
            MemoryFindingSection.VDSO -> 4
            MemoryFindingSection.LINKER -> 5
        }
    }

    private companion object {
        private const val SWAPPED_EXEC_LABEL = "Swapped executable pages"

        private val BENIGN_ART_CODE_CACHE_MARKERS = listOf(
            "dalvik-jit-code-cache",
            "dalvik-data-code-cache",
            "dalvik-zygote-jit-code-cache",
            "dalvik-zygote-data-code-cache",
            "jit-cache",
            "jit-zygote-cache",
            "jit-code-cache",
            "zygote-jit-code-cache",
            "data-code-cache",
            "zygote-data-code-cache",
            "[anon:dalvik-jit-code-cache",
            "[anon:dalvik-data-code-cache",
            "[anon:dalvik-zygote-jit-code-cache",
            "[anon:dalvik-zygote-data-code-cache",
            "[anon_shmem:dalvik-jit-code-cache",
            "[anon_shmem:dalvik-data-code-cache",
            "[anon_shmem:dalvik-zygote-jit-code-cache",
            "[anon_shmem:dalvik-zygote-data-code-cache",
            "/dev/ashmem/jit-cache",
            "/dev/ashmem/jit-zygote-cache",
            "/dev/ashmem/dalvik-jit-code-cache",
            "/dev/ashmem/dalvik-data-code-cache",
            "/dev/ashmem/dalvik-zygote-jit-code-cache",
            "/dev/ashmem/dalvik-zygote-data-code-cache",
            "/memfd:jit-cache",
            "/memfd:/jit-cache",
            "/memfd:jit-zygote-cache",
            "/memfd:/jit-zygote-cache",
        )
    }
}
