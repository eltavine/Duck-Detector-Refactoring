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

package com.eltavine.duckdetector.features.lsposed.data.repository

import android.content.Context
import android.os.SystemClock
import com.eltavine.duckdetector.core.evidence.ScanEpoch
import com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeBridge
import com.eltavine.duckdetector.features.lsposed.data.native.LSPosedNativeTrace
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedBinderProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedBridgeFieldProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedClassProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedClassLoaderProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedDirtyPolicyProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedHookCallbackProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedLogcatProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedPackageProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedRuntimeArtifactProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedStackProbe
import com.eltavine.duckdetector.features.lsposed.data.probes.LSPosedZygotePermissionProbe
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValidityCarrierManager
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedProbe
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedReport
import com.eltavine.duckdetector.core.detector.DetectorScanner
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
    private val dirtyPolicyProbe: LSPosedDirtyPolicyProbe = LSPosedDirtyPolicyProbe(),
) : DetectorScanner<LSPosedReport> {

    private val appContext = context.applicationContext
    private val dirtyPolicyCarrierManager =
        SelinuxContextValidityCarrierManager(appContext)

    override suspend fun scan(): LSPosedReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                LSPosedReport.failed(throwable.message ?: "LSPosed scan failed.")
            }
    }

    private suspend fun scanInternal(): LSPosedReport {
        val scan = ScanEpoch.current(SystemClock::elapsedRealtimeNanos)
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
        val selinuxSnapshot = dirtyPolicyCarrierManager.collectSnapshot(scan)
        val dirtyPolicyResult = dirtyPolicyProbe.run(selinuxSnapshot)
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val nativeSignals = nativeSnapshot.traces.mapIndexed(::nativeSignal)
        val dirtyPolicySignals = dirtyPolicyResult.signals

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
            addAll(dirtyPolicySignals)
            addAll(nativeSignals)
        }

        return LSPosedReport(
            stage = LSPosedStage.READY,
            nativeAvailable = nativeSnapshot.available,
            nativeMapsAvailable = nativeSnapshot.mapsAvailable,
            nativeHeapAvailable = nativeSnapshot.heapAvailable,
            zygotePermissionAvailable = zygotePermissionResult.available,
            runtimeArtifactAvailable = runtimeArtifactResult.available,
            logcatAvailable = logcatResult.available,
            dirtyPolicyAvailable = dirtyPolicyResult.available,
            lsposedPolicyRuleExposed = dirtyPolicyResult.lsposedFileReadAllowed == true &&
                dirtyPolicyResult.lsposedFileReadTrusted,
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
                dirtyPolicyResult = dirtyPolicyResult,
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

    private fun nativeSignal(
        index: Int,
        trace: LSPosedNativeTrace,
    ): LSPosedSignal {
        return LSPosedSignal(
            id = "native_${trace.group.lowercase()}_$index",
            probe = LSPosedProbe.NATIVE_TRACE,
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
