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

package com.eltavine.duckdetector.features.lsposed.data.repository

import android.content.Context
import com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeBridge
import com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeSnapshot
import com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeTrace
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedBinderProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedBridgeFieldProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedBridgeFieldProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedClassProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedClassLoaderProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedClassLoaderProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedHookCallbackProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedHookCallbackProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedLogcatProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedLogcatProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedPackageProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedRuntimeArtifactProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedRuntimeArtifactProbeResult
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedStackProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedZygotePermissionProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedZygotePermissionProbeResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodResult
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class LSPosedRepository(
    context: Context,
    private val nativeBridge: LSPosedNativeBridge = LSPosedNativeBridge(),
    private val classProbe: LSPosedClassProbe = LSPosedClassProbe(),
    private val classLoaderProbe: LSPosedClassLoaderProbe = LSPosedClassLoaderProbe(),
    private val bridgeFieldProbe: LSPosedBridgeFieldProbe = LSPosedBridgeFieldProbe(),
    private val packageProbe: LSPosedPackageProbe = LSPosedPackageProbe(),
    private val stackProbe: LSPosedStackProbe = LSPosedStackProbe(),
    private val hookCallbackProbe: LSPosedHookCallbackProbe = LSPosedHookCallbackProbe(),
    private val binderProbe: LSPosedBinderProbe = LSPosedBinderProbe(),
    private val zygotePermissionProbe: LSPosedZygotePermissionProbe = LSPosedZygotePermissionProbe(),
    private val runtimeArtifactProbe: LSPosedRuntimeArtifactProbe = LSPosedRuntimeArtifactProbe(),
    private val logcatProbe: LSPosedLogcatProbe = LSPosedLogcatProbe(),
) {

    private val appContext = context.applicationContext

    suspend fun scan(): LSPosedReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                LSPosedReport.failed(throwable.message ?: "LSPosed scan failed.")
            }
    }

    private fun scanInternal(): LSPosedReport {
        val classResult = classProbe.run()
        val classLoaderResult = classLoaderProbe.run()
        val bridgeFieldResult = bridgeFieldProbe.run()
        val packageResult = packageProbe.run(appContext)
        val stackResult = stackProbe.run()
        val hookCallbackResult = hookCallbackProbe.run()
        val binderResult = binderProbe.run()
        val zygotePermissionResult = zygotePermissionProbe.run(appContext)
        val runtimeArtifactResult = runtimeArtifactProbe.run(appContext.packageName)
        val logcatResult = logcatProbe.run()
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val nativeSignals = nativeSnapshot.traces.mapIndexed(::nativeSignal)

        val signals = buildList {
            addAll(classResult.signals)
            addAll(classLoaderResult.signals)
            addAll(bridgeFieldResult.signals)
            addAll(packageResult.signals)
            addAll(stackResult.signals)
            addAll(hookCallbackResult.signals)
            addAll(binderResult.signals)
            addAll(zygotePermissionResult.signals)
            addAll(runtimeArtifactResult.signals)
            addAll(logcatResult.signals)
            addAll(nativeSignals)
        }

        return LSPosedReport(
            stage = LSPosedStage.READY,
            nativeAvailable = nativeSnapshot.available,
            runtimeArtifactAvailable = runtimeArtifactResult.available,
            logcatAvailable = logcatResult.available,
            packageVisibility = packageResult.packageVisibility,
            signals = signals,
            methods = buildMethods(
                classHitCount = classResult.hitCount,
                classLoaderResult = classLoaderResult,
                bridgeFieldResult = bridgeFieldResult,
                managerPackageCount = packageResult.managerPackageCount,
                moduleAppCount = packageResult.moduleAppCount,
                packageVisibility = packageResult.packageVisibility,
                stackHitCount = stackResult.hitCount,
                hookCallbackResult = hookCallbackResult,
                binderHitCount = binderResult.hitCount,
                zygotePermissionResult = zygotePermissionResult,
                runtimeArtifactResult = runtimeArtifactResult,
                logcatResult = logcatResult,
                nativeSnapshot = nativeSnapshot,
                signals = signals,
            ),
            managerPackageCount = packageResult.managerPackageCount,
            moduleAppCount = packageResult.moduleAppCount,
            classHitCount = classResult.hitCount,
            classLoaderHitCount = classLoaderResult.hitCount,
            bridgeFieldHitCount = bridgeFieldResult.hitCount,
            stackHitCount = stackResult.hitCount,
            callbackHitCount = hookCallbackResult.hitCount,
            binderHitCount = binderResult.hitCount,
            runtimeArtifactHitCount = runtimeArtifactResult.hitCount,
            logcatHitCount = logcatResult.hitCount,
            nativeMapsHitCount = nativeSnapshot.mapsHitCount,
            nativeHeapHitCount = nativeSnapshot.heapHitCount,
            nativeHeapScannedRegions = nativeSnapshot.heapScannedRegions,
        )
    }

    private fun buildMethods(
        classHitCount: Int,
        classLoaderResult: LSPosedClassLoaderProbeResult,
        bridgeFieldResult: LSPosedBridgeFieldProbeResult,
        managerPackageCount: Int,
        moduleAppCount: Int,
        packageVisibility: LSPosedPackageVisibility,
        stackHitCount: Int,
        hookCallbackResult: LSPosedHookCallbackProbeResult,
        binderHitCount: Int,
        zygotePermissionResult: LSPosedZygotePermissionProbeResult,
        runtimeArtifactResult: LSPosedRuntimeArtifactProbeResult,
        logcatResult: LSPosedLogcatProbeResult,
        nativeSnapshot: LSPosedNativeSnapshot,
        signals: List<LSPosedSignal>,
    ): List<LSPosedMethodResult> {
        return listOf(
            LSPosedMethodResult(
                label = "Class load",
                summary = if (classHitCount > 0) "$classHitCount hit(s)" else "Clean",
                outcome = if (classHitCount > 0) LSPosedMethodOutcome.DETECTED else LSPosedMethodOutcome.CLEAN,
                detail = "Resolve known Xposed, libXposed, and LSPosed runtime classes through boot and app-facing class loaders.",
            ),
            LSPosedMethodResult(
                label = "ClassLoader chain",
                summary = probeSummary(classLoaderResult.signals),
                outcome = probeOutcome(classLoaderResult.signals, available = true),
                detail = "Walks app-facing ClassLoader parent chains and flags loader names or chain depth that resemble LSPosed/Xposed injection.",
            ),
            LSPosedMethodResult(
                label = "XposedBridge fields",
                summary = probeSummary(bridgeFieldResult.signals),
                outcome = probeOutcome(bridgeFieldResult.signals, available = true),
                detail = "Reflects XposedBridge.disableHooks and XposedBridge.sHookedMethodCallbacks to confirm live bridge state rather than class residue alone.",
            ),
            LSPosedMethodResult(
                label = "Package catalog",
                summary = when {
                    managerPackageCount > 0 -> "$managerPackageCount installed"
                    packageVisibility == LSPosedPackageVisibility.FULL -> "Clean"
                    packageVisibility == LSPosedPackageVisibility.RESTRICTED -> "Restricted"
                    else -> "Unknown"
                },
                outcome = when {
                    managerPackageCount > 0 -> LSPosedMethodOutcome.WARNING
                    packageVisibility == LSPosedPackageVisibility.FULL -> LSPosedMethodOutcome.CLEAN
                    else -> LSPosedMethodOutcome.SUPPORT
                },
                detail = "Checks for LSPosed, LSPatch, EdXposed, Xposed installer, TaiChi, VirtualXposed, and common module-manager packages.",
            ),
            LSPosedMethodResult(
                label = "Xposed meta-data",
                summary = when {
                    moduleAppCount > 0 -> "$moduleAppCount module(s)"
                    packageVisibility == LSPosedPackageVisibility.FULL -> "Clean"
                    packageVisibility == LSPosedPackageVisibility.RESTRICTED -> "Restricted"
                    else -> "Unknown"
                },
                outcome = when {
                    moduleAppCount > 0 -> LSPosedMethodOutcome.WARNING
                    packageVisibility == LSPosedPackageVisibility.FULL -> LSPosedMethodOutcome.CLEAN
                    else -> LSPosedMethodOutcome.SUPPORT
                },
                detail = "Scans installed app manifest meta-data such as xposedmodule, xposedminversion, and xposedscope.",
            ),
            LSPosedMethodResult(
                label = "Stack trace",
                summary = if (stackHitCount > 0) "$stackHitCount matched" else "Clean",
                outcome = if (stackHitCount > 0) LSPosedMethodOutcome.DETECTED else LSPosedMethodOutcome.CLEAN,
                detail = "Analyzes current-thread and synthetic throwable stacks for XposedBridge, LSPosedBridge, LSPHooker_, and related hook callback tokens.",
            ),
            LSPosedMethodResult(
                label = "Hook callbacks",
                summary = probeSummary(hookCallbackResult.signals),
                outcome = probeOutcome(hookCallbackResult.signals, available = true),
                detail = "Checks whether the default uncaught-exception handler class points back to Xposed or LSPosed runtime code.",
            ),
            LSPosedMethodResult(
                label = "Binder bridge",
                summary = if (binderHitCount > 0) "$binderHitCount hit(s)" else "Clean",
                outcome = if (binderHitCount > 0) LSPosedMethodOutcome.DETECTED else LSPosedMethodOutcome.CLEAN,
                detail = "Probes activity and serial Binder services for LSPosed bridge transaction behavior and descriptors.",
            ),
            LSPosedMethodResult(
                label = "Zygote permissions",
                summary = when {
                    !zygotePermissionResult.available -> "Unavailable"
                    zygotePermissionResult.mismatchCount > 0 -> "${zygotePermissionResult.mismatchCount} mismatch(es)"
                    zygotePermissionResult.auditedGrantCount > 0 -> "${zygotePermissionResult.auditedGrantCount} grant(s) clean"
                    else -> "No mapped grants"
                },
                outcome = when {
                    !zygotePermissionResult.available -> LSPosedMethodOutcome.SUPPORT
                    zygotePermissionResult.mismatchCount > 0 -> LSPosedMethodOutcome.DETECTED
                    zygotePermissionResult.auditedGrantCount > 0 -> LSPosedMethodOutcome.CLEAN
                    else -> LSPosedMethodOutcome.SUPPORT
                },
                detail = "Compares granted app permissions against the zygote-assigned supplemental GIDs exposed through /proc/self/status. ${zygotePermissionResult.detail}",
            ),
            LSPosedMethodResult(
                label = "Runtime artifacts",
                summary = runtimeProbeSummary(runtimeArtifactResult),
                outcome = probeOutcome(
                    signals = runtimeArtifactResult.signals,
                    available = runtimeArtifactResult.available,
                ),
                detail = runtimeArtifactResult.failureReason
                    ?: "Scans /proc/self/net/unix, /proc/self/fd, and environment variables for LSPosed/Xposed runtime residue that leaks into the current app process.",
            ),
            LSPosedMethodResult(
                label = "Logcat leaks",
                summary = runtimeProbeSummary(logcatResult),
                outcome = probeOutcome(
                    signals = logcatResult.signals,
                    available = logcatResult.available,
                ),
                detail = logcatResult.failureReason
                    ?: "Samples recent logcat buffers for LSPosed tags, control messages, bridge traces, and org.lsposed.daemon process leakage without requesting extra permissions.",
            ),
            LSPosedMethodResult(
                label = "Native maps",
                summary = when {
                    nativeSnapshot.mapsHitCount > 0 -> "${nativeSnapshot.mapsHitCount} hit(s)"
                    nativeSnapshot.available -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    nativeSnapshot.mapsHitCount > 0 -> LSPosedMethodOutcome.DETECTED
                    nativeSnapshot.available -> LSPosedMethodOutcome.CLEAN
                    else -> LSPosedMethodOutcome.SUPPORT
                },
                detail = "Scans /proc/self/maps for LSPosed, XposedBridge, libXposed, LSPlant, EdXposed, and LSPatch runtime mappings.",
            ),
            LSPosedMethodResult(
                label = "Native heap",
                summary = when {
                    nativeSnapshot.heapHitCount > 0 -> "${nativeSnapshot.heapHitCount} residual(s)"
                    nativeSnapshot.heapAvailable -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    nativeSnapshot.heapHitCount > 0 -> LSPosedMethodOutcome.DETECTED
                    nativeSnapshot.heapAvailable -> LSPosedMethodOutcome.CLEAN
                    else -> LSPosedMethodOutcome.SUPPORT
                },
                detail = "Samples readable Dalvik heap regions through /proc/self/mem for LSPosed and Xposed keyword residuals.",
            ),
            LSPosedMethodResult(
                label = "Native library",
                summary = if (nativeSnapshot.available) "Loaded" else "Unavailable",
                outcome = if (nativeSnapshot.available) LSPosedMethodOutcome.CLEAN else LSPosedMethodOutcome.SUPPORT,
                detail = "JNI-backed maps and heap probes for LSPosed-specific runtime evidence.",
            ),
            LSPosedMethodResult(
                label = "Signal summary",
                summary = when {
                    signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> "${signals.count { it.severity == LSPosedSignalSeverity.DANGER }} strong"
                    signals.isNotEmpty() -> "${signals.size} weak"
                    else -> "Clean"
                },
                outcome = when {
                    signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
                    signals.isNotEmpty() -> LSPosedMethodOutcome.WARNING
                    else -> LSPosedMethodOutcome.CLEAN
                },
                detail = "Direct runtime signals come from classes, stack traces, Binder bridges, and native traces; package-only signals are softer residue.",
            ),
        )
    }

    private fun probeSummary(
        signals: List<LSPosedSignal>,
    ): String {
        if (signals.isEmpty()) {
            return "Clean"
        }

        val dangerCount = signals.count { it.severity == LSPosedSignalSeverity.DANGER }
        val warningCount = signals.count { it.severity == LSPosedSignalSeverity.WARNING }
        return when {
            dangerCount > 0 && warningCount > 0 -> "${dangerCount + warningCount} hit(s)"
            dangerCount > 0 -> "$dangerCount hit(s)"
            else -> "$warningCount review"
        }
    }

    private fun runtimeProbeSummary(
        result: Any,
    ): String {
        return when (result) {
            is LSPosedRuntimeArtifactProbeResult -> when {
                !result.available -> "Unavailable"
                result.signals.isEmpty() -> "Clean"
                else -> probeSummary(result.signals)
            }

            is LSPosedLogcatProbeResult -> when {
                !result.available -> "Unavailable"
                result.signals.isEmpty() -> "Clean"
                else -> probeSummary(result.signals)
            }

            else -> "Unavailable"
        }
    }

    private fun probeOutcome(
        signals: List<LSPosedSignal>,
        available: Boolean,
    ): LSPosedMethodOutcome {
        return when {
            !available -> LSPosedMethodOutcome.SUPPORT
            signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
            signals.any { it.severity == LSPosedSignalSeverity.WARNING } -> LSPosedMethodOutcome.WARNING
            else -> LSPosedMethodOutcome.CLEAN
        }
    }

    private fun nativeSignal(
        index: Int,
        trace: LSPosedNativeTrace,
    ): LSPosedSignal {
        return LSPosedSignal(
            id = "native_${trace.group.lowercase()}_$index",
            label = trace.label,
            value = if (trace.group == "HEAP") "Residual" else "Mapped",
            group = LSPosedSignalGroup.NATIVE,
            severity = when (trace.severity) {
                "DANGER" -> LSPosedSignalSeverity.DANGER
                else -> LSPosedSignalSeverity.WARNING
            },
            detail = buildString {
                append(trace.group)
                appendLine()
                append(trace.detail)
            },
            detailMonospace = true,
        )
    }
}
