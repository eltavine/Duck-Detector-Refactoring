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

package com.eltavine.duckdetector.features.zygisk.data.repository

import android.content.Context
import android.os.Debug
import com.eltavine.duckdetector.features.zygisk.data.fdtrap.ZygiskFdTrapDetectionResult
import com.eltavine.duckdetector.features.zygisk.data.fdtrap.ZygiskFdTrapManager
import com.eltavine.duckdetector.features.zygisk.data.fdtrap.ZygiskFdTrapNativeBridge
import com.eltavine.duckdetector.features.zygisk.data.native.ZygiskNativeBridge
import com.eltavine.duckdetector.features.zygisk.data.native.ZygiskNativeSnapshot
import com.eltavine.duckdetector.features.zygisk.data.native.ZygiskNativeTrace
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethod
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethodOutcome
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskMethodResult
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskReport
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignal
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalGroup
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskSignalSeverity
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskStage
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskAtexitState
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlinx.coroutines.withContext

class ZygiskRepository(
    context: Context,
    private val nativeBridge: ZygiskNativeBridge = ZygiskNativeBridge(),
    private val fdTrapManager: ZygiskFdTrapManager = ZygiskFdTrapManager(),
) : DetectorScanner<ZygiskReport> {

    private val appContext = context.applicationContext

    override suspend fun scan(): ZygiskReport = withContext(Dispatchers.IO) {
        runCatching {
            val snapshot = nativeBridge.collectSnapshot()
            val fdTrap = if (shouldSkipFdTrap()) {
                ZygiskFdTrapDetectionResult.fromResultCode(
                    resultCode = ZygiskFdTrapNativeBridge.RESULT_SKIPPED,
                    detail = "FD trap was skipped because the app process is running under a debugger or Android Studio startup agent, which distorts specialization behavior and has been unstable on this device.",
                )
            } else {
                withContext(Dispatchers.IO) { fdTrapManager.detect(appContext) }
            }
            buildReport(
                fdTrap = fdTrap,
                snapshot = snapshot,
            )
        }.getOrElse { throwable ->
            ZygiskReport.failed(throwable.message ?: "Zygisk scan failed.")
        }
    }

    private fun buildReport(
        fdTrap: ZygiskFdTrapDetectionResult,
        snapshot: ZygiskNativeSnapshot,
    ): ZygiskReport {
        val signals = buildSignals(fdTrap, snapshot)
        return ZygiskReport(
            stage = ZygiskStage.READY,
            fdTrapAvailable = fdTrap.available,
            fdTrapDetected = fdTrap.detected,
            nativeAvailable = snapshot.available,
            atexitTable = snapshot.atexitTable,
            heapAvailable = snapshot.heapAvailable,
            nativeStrongHitCount = snapshot.strongHitCount,
            heuristicHitCount = snapshot.heuristicHitCount,
            tracerPid = snapshot.tracerPid,
            signals = signals.sortedWith(
                compareBy<ZygiskSignal> { severityPriority(it.severity) }
                    .thenBy { if (it.direct) 0 else 1 }
                    .thenBy { groupPriority(it.group) }
                    .thenBy { it.label },
            ),
            methods = buildMethods(fdTrap, snapshot),
            references = ZygiskReport.defaultReferences(),
        )
    }

    private fun buildSignals(
        fdTrap: ZygiskFdTrapDetectionResult,
        snapshot: ZygiskNativeSnapshot,
    ): List<ZygiskSignal> {
        val rows = mutableListOf<ZygiskSignal>()
        if (fdTrap.detected) {
            rows += ZygiskSignal(
                id = "zygisk_fd_trap",
                label = "FD trap",
                value = fdTrap.methodName,
                group = ZygiskSignalGroup.CROSS_PROCESS,
                severity = ZygiskSignalSeverity.DANGER,
                detail = fdTrap.detail,
                direct = true,
                detailMonospace = fdTrap.detail.shouldUseMonospace(),
            )
        }
        rows += snapshot.traces.mapIndexed { index, trace ->
            ZygiskSignal(
                id = "zygisk_trace_$index",
                label = trace.label,
                value = trace.severity.toSignalValue(),
                group = trace.group.toSignalGroup(),
                severity = trace.severity.toSignalSeverity(),
                detail = trace.detail,
                direct = trace.isDirectRuntimeSignal(),
                detailMonospace = trace.detail.shouldUseMonospace(),
            )
        }
        return rows
    }

    private fun buildMethods(
        fdTrap: ZygiskFdTrapDetectionResult,
        snapshot: ZygiskNativeSnapshot,
    ): List<ZygiskMethodResult> {
        val heuristicFamilies = listOf(
            snapshot.solistHitCount,
            snapshot.vmapHitCount,
            maxOf(snapshot.atexitHitCount, if (snapshot.atexitTable.hasEvidence) 1 else 0),
            snapshot.smapsHitCount,
            snapshot.heapHitCount,
            snapshot.threadHitCount,
            snapshot.fdHitCount,
        ).count { it > 0 }

        return listOf(
            ZygiskMethodResult(
                method = ZygiskMethod.CROSS_PROCESS_FD_TRAP,
                summary = when {
                    fdTrap.detected -> fdTrap.summary
                    fdTrap.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    fdTrap.detected -> ZygiskMethodOutcome.DETECTED
                    fdTrap.available -> ZygiskMethodOutcome.CLEAN
                    else -> ZygiskMethodOutcome.SUPPORT
                },
                detail = fdTrap.detail.ifBlank {
                    "Creates a deleted-path trap descriptor in the app process and verifies it from a specialized child process."
                },
            ),
            ZygiskMethodResult(
                method = ZygiskMethod.NATIVE_SNAPSHOT,
                summary = when {
                    !snapshot.available -> "Unavailable"
                    snapshot.strongHitCount > 0 || snapshot.heuristicHitCount > 0 || snapshot.atexitTable.hasEvidence -> "Signals captured"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.available -> ZygiskMethodOutcome.SUPPORT
                    snapshot.strongHitCount > 0 -> ZygiskMethodOutcome.DETECTED
                    snapshot.heuristicHitCount > 0 || snapshot.atexitTable.hasEvidence -> ZygiskMethodOutcome.WARNING
                    else -> ZygiskMethodOutcome.CLEAN
                },
                detail = "Collects linker, namespace, maps, smaps, thread, fd, and heap traces from the current app process.",
            ),
            ZygiskMethodResult(
                method = ZygiskMethod.LINKER_AND_NAMESPACE,
                summary = when {
                    snapshot.linkerHookHitCount > 0 || snapshot.namespaceHitCount > 0 -> "Bypassed"
                    !snapshot.available -> "Unavailable"
                    else -> "Clean"
                },
                outcome = when {
                    snapshot.linkerHookHitCount > 0 || snapshot.namespaceHitCount > 0 -> ZygiskMethodOutcome.DETECTED
                    !snapshot.available -> ZygiskMethodOutcome.SUPPORT
                    else -> ZygiskMethodOutcome.CLEAN
                },
                detail = "Checks whether linker entry points still belong to the expected loader and whether restricted-path libraries appear in the current process. The check that an entry point immediately branches out of the loader decodes arm64 instructions, so on other ABIs only the owning-image check runs.",
            ),
            ZygiskMethodResult(
                method = ZygiskMethod.MAPS_AND_SMAPS,
                summary = when {
                    !snapshot.available -> "Unavailable"
                    snapshot.vmapHitCount + snapshot.smapsHitCount > 0 -> "Anomalies"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.available -> ZygiskMethodOutcome.SUPPORT
                    snapshot.vmapHitCount + snapshot.smapsHitCount > 0 -> ZygiskMethodOutcome.WARNING
                    else -> ZygiskMethodOutcome.CLEAN
                },
                detail = "Looks for suspicious executable mappings, deleted loaders, JIT drift, and dirty system library pages.",
            ),
            ZygiskMethodResult(
                method = ZygiskMethod.THREADS_AND_FDS,
                summary = when {
                    !snapshot.available -> "Unavailable"
                    snapshot.tracerPid > 0 || snapshot.threadHitCount + snapshot.fdHitCount > 0 -> "Residue"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.available -> ZygiskMethodOutcome.SUPPORT
                    snapshot.tracerPid > 0 -> ZygiskMethodOutcome.DETECTED
                    snapshot.threadHitCount + snapshot.fdHitCount > 0 -> ZygiskMethodOutcome.WARNING
                    else -> ZygiskMethodOutcome.CLEAN
                },
                detail = "Correlates TracerPid, suspicious thread names, and open descriptor targets that frequently survive runtime tampering stacks.",
            ),
            ZygiskMethodResult(
                method = ZygiskMethod.ATEXIT_HANDLERS,
                summary = if (snapshot.atexitTable.hasEvidence) "Residue observed" else snapshot.atexitTable.state.label,
                outcome = when {
                    snapshot.atexitTable.hasEvidence -> ZygiskMethodOutcome.WARNING
                    snapshot.atexitTable.state == ZygiskAtexitState.COLLECTED -> ZygiskMethodOutcome.CLEAN
                    else -> ZygiskMethodOutcome.SUPPORT
                },
                detail = snapshot.atexitTable.detail + " Entries: ${snapshot.atexitTable.entries}; " +
                    "cleared: ${snapshot.atexitTable.nullEntries}; runtime-adjacent gaps: ${snapshot.atexitTable.anchoredGaps}; " +
                    "anonymous callbacks: ${snapshot.atexitTable.anonymousCallbacks}. " +
                    "These observations do not identify an injection framework or version.",
            ),
            ZygiskMethodResult(
                method = ZygiskMethod.SOLIST_ATEXIT_HEAP,
                summary = when {
                    !snapshot.available -> "Unavailable"
                    heuristicFamilies > 0 -> "Drift"
                    else -> "Clean"
                },
                outcome = when {
                    !snapshot.available -> ZygiskMethodOutcome.SUPPORT
                    heuristicFamilies > 0 -> ZygiskMethodOutcome.WARNING
                    else -> ZygiskMethodOutcome.CLEAN
                },
                detail = "Uses weaker corroboration probes for module unload drift, atexit routing, and jemalloc free-kept entropy.",
            ),
        )
    }

    private fun String.toSignalGroup(): ZygiskSignalGroup {
        return when (uppercase()) {
            "CROSS_PROCESS" -> ZygiskSignalGroup.CROSS_PROCESS
            "RUNTIME" -> ZygiskSignalGroup.RUNTIME
            "LINKER" -> ZygiskSignalGroup.LINKER
            "HEAP" -> ZygiskSignalGroup.HEAP
            "THREADS" -> ZygiskSignalGroup.THREADS
            "FD" -> ZygiskSignalGroup.FD
            else -> ZygiskSignalGroup.MAPS
        }
    }

    private fun String.toSignalSeverity(): ZygiskSignalSeverity {
        return when (uppercase()) {
            "DANGER" -> ZygiskSignalSeverity.DANGER
            else -> ZygiskSignalSeverity.WARNING
        }
    }

    private fun String.toSignalValue(): String {
        return when (uppercase()) {
            "DANGER" -> "Danger"
            else -> "Review"
        }
    }

    private fun ZygiskNativeTrace.isDirectRuntimeSignal(): Boolean {
        return label in DIRECT_RUNTIME_LABELS
    }

    private fun String.shouldUseMonospace(): Boolean {
        return contains("0x") ||
                contains("/proc/") ||
                contains("/data/") ||
                contains("/system/") ||
                contains(".so") ||
                contains("memfd:") ||
                contains("(deleted)")
    }

    private fun severityPriority(
        severity: ZygiskSignalSeverity,
    ): Int {
        return when (severity) {
            ZygiskSignalSeverity.DANGER -> 0
            ZygiskSignalSeverity.WARNING -> 1
        }
    }

    private fun groupPriority(
        group: ZygiskSignalGroup,
    ): Int {
        return when (group) {
            ZygiskSignalGroup.CROSS_PROCESS -> 0
            ZygiskSignalGroup.RUNTIME -> 1
            ZygiskSignalGroup.LINKER -> 2
            ZygiskSignalGroup.MAPS -> 3
            ZygiskSignalGroup.HEAP -> 4
            ZygiskSignalGroup.THREADS -> 5
            ZygiskSignalGroup.FD -> 6
        }
    }

    companion object {
        private val DIRECT_RUNTIME_LABELS = setOf(
            "FD trap",
            "TracerPid",
            "Namespace bypass",
            "Linker hook",
            "NeoZygisk environment marker",
        )
    }

    private fun shouldSkipFdTrap(): Boolean {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            return true
        }
        return runCatching {
            File("/proc/self/maps").useLines { lines ->
                lines.any { line ->
                    line.contains("startup_agents") ||
                            line.contains(".studio/instruments") ||
                            line.contains("agent.so")
                }
            }
        }.getOrDefault(false)
    }
}
