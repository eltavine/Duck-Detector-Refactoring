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

package com.eltavine.duckdetector.features.virtualization.data.repository

import android.content.Context
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.startup.preload.EarlyVirtualizationPreloadResult
import com.eltavine.duckdetector.core.startup.preload.EarlyVirtualizationPreloadSignal
import com.eltavine.duckdetector.core.startup.preload.EarlyVirtualizationPreloadStore
import com.eltavine.duckdetector.features.virtualization.data.native.SacrificialSyscallPackResult
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeFinding
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeSnapshot
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationTrapResult
import com.eltavine.duckdetector.features.virtualization.data.probes.AsmCounterTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.AsmRawSyscallTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.NativeSyscallParityTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.NativeTimingTrapProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationBuildProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationPropertyProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbeResult
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppsCatalog
import com.eltavine.duckdetector.features.virtualization.data.service.VirtualizationIsolatedProbeManager
import com.eltavine.duckdetector.features.virtualization.data.service.VirtualizationProbeManager
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationImpact
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodResult
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationReport
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class VirtualizationProcessInfo(
    val filesDir: String = "",
    val cacheDir: String = "",
    val codePath: String = "",
) {
    companion object {
        fun fromContext(context: Context?): VirtualizationProcessInfo {
            val appContext = context?.applicationContext ?: return VirtualizationProcessInfo()
            return VirtualizationProcessInfo(
                filesDir = runCatching { appContext.filesDir.absolutePath }.getOrDefault(""),
                cacheDir = runCatching { appContext.cacheDir.absolutePath }.getOrDefault(""),
                codePath = runCatching { appContext.applicationInfo.sourceDir }.getOrDefault(""),
            )
        }
    }
}

internal data class ConsistencyComputation(
    val crossProcessSignals: List<VirtualizationSignal> = emptyList(),
    val isolatedSignals: List<VirtualizationSignal> = emptyList(),
    val mountAnchorDriftCount: Int = 0,
) {
    val allSignals: List<VirtualizationSignal>
        get() = crossProcessSignals + isolatedSignals
}

class VirtualizationRepository(
    context: Context? = null,
    private val propertyProbe: VirtualizationPropertyProbe = VirtualizationPropertyProbe(),
    private val buildProbe: VirtualizationBuildProbe = VirtualizationBuildProbe(),
    private val serviceProbe: VirtualizationServiceProbe = VirtualizationServiceProbe(),
    private val dexPathProbe: DexPathProbe = DexPathProbe(context?.applicationContext),
    private val uidIdentityProbe: UidIdentityProbe = UidIdentityProbe(context?.applicationContext),
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
    private val hostAppProbe: VirtualizationHostAppProbe = VirtualizationHostAppProbe(
        context?.applicationContext,
    ),
    private val probeManager: VirtualizationProbeManager = VirtualizationProbeManager(
        context?.applicationContext,
    ),
    private val isolatedProbeManager: VirtualizationIsolatedProbeManager =
        VirtualizationIsolatedProbeManager(context?.applicationContext),
    private val nativeTimingTrapProbe: NativeTimingTrapProbe = NativeTimingTrapProbe(nativeBridge),
    private val nativeSyscallParityTrapProbe: NativeSyscallParityTrapProbe =
        NativeSyscallParityTrapProbe(nativeBridge),
    private val asmCounterTrapProbe: AsmCounterTrapProbe = AsmCounterTrapProbe(nativeBridge),
    private val asmRawSyscallTrapProbe: AsmRawSyscallTrapProbe =
        AsmRawSyscallTrapProbe(nativeBridge),
    private val preloadResultProvider: () -> EarlyVirtualizationPreloadResult = {
        EarlyVirtualizationPreloadStore.currentResult()
    },
    private val processInfoProvider: () -> VirtualizationProcessInfo = {
        VirtualizationProcessInfo.fromContext(context?.applicationContext)
    },
) {

    suspend fun scan(): VirtualizationReport = withContext(Dispatchers.Default) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                VirtualizationReport.failed(throwable.message ?: "Virtualization scan failed.")
            }
    }

    internal suspend fun scanInternal(): VirtualizationReport {
        val propertySignals = propertyProbe.probe()
        val buildSignals = buildProbe.probe()
        val serviceResult = serviceProbe.probe()
        val dexPathResult = dexPathProbe.probe()
        val uidIdentityResult = uidIdentityProbe.probe()
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val preloadResult = preloadResultProvider()
        val remoteSnapshot = probeManager.collect()
        val isolatedSnapshot = isolatedProbeManager.collect()
        val hostAppResult = hostAppProbe.probe()
        val mainProcessInfo = processInfoProvider()
        val nativeTimingTrap = nativeTimingTrapProbe.probe()
        val nativeSyscallParityTrap = nativeSyscallParityTrapProbe.probe()
        val asmCounterTrap = asmCounterTrapProbe.probe()
        val asmRawSyscallTrap = asmRawSyscallTrapProbe.probe()
        val syscallPackResult = probeManager.runSacrificialSyscallPack()

        val nativeSignals = nativeSnapshot.findings.map(::nativeFindingToSignal)
        val preloadSignals = buildPreloadSignals(preloadResult)
        val consistency = buildConsistencySignals(
            nativeSnapshot = nativeSnapshot,
            preloadResult = preloadResult,
            remoteSnapshot = remoteSnapshot,
            isolatedSnapshot = isolatedSnapshot,
            mainProcessInfo = mainProcessInfo,
            dexPathResult = dexPathResult,
            uidIdentityResult = uidIdentityResult,
        )
        val hostSignals = buildHostAppSignals(hostAppResult)
        val honeypotSignals = buildHoneypotSignals(
            nativeTimingTrap = nativeTimingTrap,
            nativeSyscallParityTrap = nativeSyscallParityTrap,
            asmCounterTrap = asmCounterTrap,
            asmRawSyscallTrap = asmRawSyscallTrap,
            syscallPackResult = syscallPackResult,
        )

        val signals = (
                propertySignals +
                        buildSignals +
                        serviceResult.signals +
                        dexPathResult.signals +
                        uidIdentityResult.signals +
                        nativeSignals +
                        preloadSignals +
                        consistency.allSignals +
                        hostSignals +
                        honeypotSignals
                )
            .distinctBy { it.id }
            .sortedWith(
                compareBy<VirtualizationSignal> { severityPriority(it.severity) }
                    .thenBy { groupPriority(it.group) }
                    .thenBy { it.label },
            )

        val runtimeSignals = signals.filter { it.group == VirtualizationSignalGroup.RUNTIME }
        val graphicsSignals = runtimeSignals.filter {
            it.label.contains("renderer", ignoreCase = true) ||
                    it.label.contains("graphics", ignoreCase = true)
        }
        val translationSignals =
            signals.filter { it.group == VirtualizationSignalGroup.TRANSLATION }

        return VirtualizationReport(
            stage = VirtualizationStage.READY,
            nativeAvailable = nativeSnapshot.available,
            startupPreloadAvailable = preloadResult.available,
            startupPreloadContextValid = preloadResult.isContextValid,
            crossProcessAvailable = remoteSnapshot.available,
            isolatedProcessAvailable = isolatedSnapshot.available,
            asmSupported = asmCounterTrap.supported || asmRawSyscallTrap.supported,
            eglAvailable = nativeSnapshot.eglAvailable,
            packageVisibility = hostAppResult.packageVisibility,
            dexPathEntryCount = dexPathResult.entryCount,
            dexPathHitCount = dexPathResult.hitCount,
            uidIdentityHitCount = uidIdentityResult.hitCount,
            environmentHitCount = countHits(signals, VirtualizationSignalGroup.ENVIRONMENT),
            translationHitCount = countHits(signals, VirtualizationSignalGroup.TRANSLATION),
            runtimeArtifactHitCount = countHits(signals, VirtualizationSignalGroup.RUNTIME),
            consistencyHitCount = countHits(signals, VirtualizationSignalGroup.CONSISTENCY),
            isolatedConsistencyHitCount = countHits(
                consistency.isolatedSignals,
                VirtualizationSignalGroup.CONSISTENCY,
            ),
            mountAnchorDriftCount = consistency.mountAnchorDriftCount,
            mountNamespaceAvailable = nativeSnapshot.mountNamespaceInode.isNotBlank(),
            honeypotHitCount = countHits(signals, VirtualizationSignalGroup.HONEYPOT),
            syscallPackSupported = syscallPackResult.supported,
            syscallPackHitCount = syscallPackResult.hitCount,
            hostAppCorroborationCount = signals.count { it.group == VirtualizationSignalGroup.HOST_APPS },
            mapLineCount = nativeSnapshot.mapLineCount,
            fdCount = nativeSnapshot.fdCount,
            mountInfoCount = nativeSnapshot.mountInfoCount,
            signals = signals,
            methods = buildMethods(
                propertySignals = propertySignals + buildSignals + serviceResult.signals,
                dexPathResult = dexPathResult,
                uidIdentityResult = uidIdentityResult,
                runtimeSignals = runtimeSignals.filterNot { it in graphicsSignals },
                graphicsSignals = graphicsSignals,
                translationSignals = translationSignals,
                preloadSignals = preloadSignals,
                preloadResult = preloadResult,
                crossProcessSignals = consistency.crossProcessSignals,
                isolatedSignals = consistency.isolatedSignals,
                remoteSnapshot = remoteSnapshot,
                isolatedSnapshot = isolatedSnapshot,
                hostAppResult = hostAppResult,
                nativeTimingTrap = nativeTimingTrap,
                nativeSyscallParityTrap = nativeSyscallParityTrap,
                asmCounterTrap = asmCounterTrap,
                asmRawSyscallTrap = asmRawSyscallTrap,
                syscallPackResult = syscallPackResult,
                listedServiceCount = serviceResult.listedServiceCount,
            ),
            impacts = buildImpacts(signals, hostAppResult),
        )
    }

    private fun countHits(
        signals: List<VirtualizationSignal>,
        group: VirtualizationSignalGroup
    ): Int {
        return signals.count {
            it.group == group &&
                    it.severity in setOf(
                VirtualizationSignalSeverity.WARNING,
                VirtualizationSignalSeverity.DANGER,
            )
        }
    }

    private data class ParsedMountAnchor(
        val mountId: String,
        val majorMinor: String,
        val root: String,
        val mountPoint: String,
        val fsType: String,
        val source: String,
    ) {
        val semanticKey: String
            get() = listOf(
                normalizeMountField(majorMinor),
                normalizeMountPath(root),
                normalizeMountPath(mountPoint),
                normalizeMountField(fsType),
                normalizeMountPath(source),
            ).joinToString("|")

        fun semanticSummary(): String {
            return "dev=$majorMinor root=$root point=$mountPoint fs=$fsType source=$source"
        }

        companion object {
            fun parse(raw: String): ParsedMountAnchor? {
                if (raw.isBlank()) {
                    return null
                }
                val parts = raw.split('|', limit = 6)
                if (parts.size != 6) {
                    return null
                }
                return ParsedMountAnchor(
                    mountId = parts[0].trim(),
                    majorMinor = parts[1].trim(),
                    root = parts[2].trim(),
                    mountPoint = parts[3].trim(),
                    fsType = parts[4].trim(),
                    source = parts[5].trim(),
                )
            }

            private fun normalizeMountField(value: String): String {
                return value.trim().lowercase()
            }

            private fun normalizeMountPath(value: String): String {
                val normalized = value.trim()
                    .replace('\\', '/')
                    .replace(Regex("/+"), "/")
                return if (normalized.length > 1 && normalized.endsWith('/')) {
                    normalized.dropLast(1).lowercase()
                } else {
                    normalized.lowercase()
                }
            }
        }
    }

    private fun nativeFindingToSignal(finding: VirtualizationNativeFinding): VirtualizationSignal {
        return VirtualizationSignal(
            id = "virt_native_${finding.group}_${finding.label}_${finding.value}",
            label = finding.label,
            value = finding.value,
            group = when (finding.group.uppercase()) {
                "ENVIRONMENT" -> VirtualizationSignalGroup.ENVIRONMENT
                "TRANSLATION" -> VirtualizationSignalGroup.TRANSLATION
                else -> VirtualizationSignalGroup.RUNTIME
            },
            severity = when (finding.severity.uppercase()) {
                "DANGER" -> VirtualizationSignalSeverity.DANGER
                "INFO" -> VirtualizationSignalSeverity.INFO
                "SAFE" -> VirtualizationSignalSeverity.SAFE
                else -> VirtualizationSignalSeverity.WARNING
            },
            detail = finding.detail,
            detailMonospace = finding.detail.shouldUseMonospace(),
        )
    }

    internal fun buildPreloadSignals(preloadResult: EarlyVirtualizationPreloadResult): List<VirtualizationSignal> {
        if (!preloadResult.hasRun) return emptyList()
        return preloadResult.activeSignals.map { signal ->
            VirtualizationSignal(
                id = "virt_preload_${signal.key.lowercase()}",
                label = "Startup preload ${signal.label}",
                value = if (signal.isDanger) "Detected" else "Review",
                group = if (signal == EarlyVirtualizationPreloadSignal.NATIVE_BRIDGE) {
                    VirtualizationSignalGroup.TRANSLATION
                } else {
                    VirtualizationSignalGroup.RUNTIME
                },
                severity = if (signal.isDanger) {
                    VirtualizationSignalSeverity.DANGER
                } else {
                    VirtualizationSignalSeverity.WARNING
                },
                detail = buildString {
                    append("Source=startup preload")
                    preloadResult.details.takeIf { it.isNotBlank() }?.let { detail ->
                        append(" | ")
                        append(detail)
                    }
                    preloadResult.mountNamespaceInode.takeIf { it.isNotBlank() }?.let {
                        append(" | mnt_ns=")
                        append(it)
                    }
                },
            )
        }
    }

    internal fun buildConsistencySignals(
        nativeSnapshot: VirtualizationNativeSnapshot,
        preloadResult: EarlyVirtualizationPreloadResult,
        remoteSnapshot: VirtualizationRemoteSnapshot,
        isolatedSnapshot: VirtualizationRemoteSnapshot,
        mainProcessInfo: VirtualizationProcessInfo,
        dexPathResult: DexPathProbeResult,
        uidIdentityResult: UidIdentityProbeResult,
    ): ConsistencyComputation {
        val crossSignals = mutableListOf<VirtualizationSignal>()
        val isolatedSignals = mutableListOf<VirtualizationSignal>()
        var mountAnchorDriftCount = 0

        if (remoteSnapshot.available && remoteSnapshot.profile == VirtualizationRemoteProfile.REGULAR) {
            val pathMismatches = buildList {
                if (
                    mainProcessInfo.filesDir.isNotBlank() &&
                    remoteSnapshot.filesDir.isNotBlank() &&
                    mainProcessInfo.filesDir != remoteSnapshot.filesDir
                ) add("filesDir main=${mainProcessInfo.filesDir} helper=${remoteSnapshot.filesDir}")
                if (
                    mainProcessInfo.cacheDir.isNotBlank() &&
                    remoteSnapshot.cacheDir.isNotBlank() &&
                    mainProcessInfo.cacheDir != remoteSnapshot.cacheDir
                ) add("cacheDir main=${mainProcessInfo.cacheDir} helper=${remoteSnapshot.cacheDir}")
                if (
                    mainProcessInfo.codePath.isNotBlank() &&
                    remoteSnapshot.codePath.isNotBlank() &&
                    mainProcessInfo.codePath != remoteSnapshot.codePath
                ) add("codePath main=${mainProcessInfo.codePath} helper=${remoteSnapshot.codePath}")
            }
            if (pathMismatches.isNotEmpty()) {
                crossSignals += VirtualizationSignal(
                    id = "virt_consistency_paths",
                    label = "Cross-process path drift",
                    value = "Review",
                    group = VirtualizationSignalGroup.CONSISTENCY,
                    severity = VirtualizationSignalSeverity.WARNING,
                    detail = pathMismatches.joinToString(separator = "\n"),
                    detailMonospace = true,
                )
            }

            val mainComparableArtifacts = comparableArtifactKeys(nativeSnapshot.findings)
            val helperComparableArtifacts = comparableArtifactKeys(remoteSnapshot.findings)
            val onlyInMain = (mainComparableArtifacts - helperComparableArtifacts).take(6)
            val onlyInHelper = (helperComparableArtifacts - mainComparableArtifacts).take(6)
            if (onlyInMain.isNotEmpty() || onlyInHelper.isNotEmpty()) {
                crossSignals += VirtualizationSignal(
                    id = "virt_consistency_artifacts",
                    label = "Cross-process artifact drift",
                    value = "Review",
                    group = VirtualizationSignalGroup.CONSISTENCY,
                    severity = VirtualizationSignalSeverity.WARNING,
                    detail = buildString {
                        if (onlyInMain.isNotEmpty()) {
                            append("Only in main:\n")
                            append(onlyInMain.joinToString(separator = "\n"))
                        }
                        if (onlyInHelper.isNotEmpty()) {
                            if (isNotEmpty()) append("\n\n")
                            append("Only in helper:\n")
                            append(onlyInHelper.joinToString(separator = "\n"))
                        }
                    },
                    detailMonospace = true,
                )
            }
        }

        if (
            preloadResult.hasDangerSignal &&
            nativeSnapshot.findings.none { it.severity.equals("DANGER", ignoreCase = true) }
        ) {
            crossSignals += VirtualizationSignal(
                id = "virt_consistency_preload_drift",
                label = "Startup/runtime drift",
                value = "Review",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = "Startup preload saw virtualization artifacts that were not visible from the later runtime snapshot.",
            )
        }

        val mainHasHostResidue = dexPathResult.hostPathHit || uidIdentityResult.hostPackageHit
        val helperHasHostResidue =
            remoteSnapshot.classPathEntries.any(VirtualizationHostAppsCatalog::containsHostToken) ||
                    remoteSnapshot.packagesForUid.any {
                        VirtualizationHostAppsCatalog.targetByPackage.containsKey(it)
                    }
        val isolatedHasHostResidue =
            isolatedSnapshot.classPathEntries.any(VirtualizationHostAppsCatalog::containsHostToken) ||
                    isolatedSnapshot.packagesForUid.any {
                        VirtualizationHostAppsCatalog.targetByPackage.containsKey(it)
                    }

        if ((mainHasHostResidue || helperHasHostResidue) && isolatedSnapshot.available && !isolatedHasHostResidue) {
            isolatedSignals += VirtualizationSignal(
                id = "virt_isolated_host_residue",
                label = "Isolated process stayed clean",
                value = "Danger",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.DANGER,
                detail = buildString {
                    append("Main/helper showed host classpath or UID residue while isolated process did not.\n")
                    append("mainHost=")
                    append(mainHasHostResidue)
                    append(" helperHost=")
                    append(helperHasHostResidue)
                    append(" isolatedHost=")
                    append(isolatedHasHostResidue)
                },
                detailMonospace = true,
            )
        }

        if (remoteSnapshot.available) {
            val regularAnchorResult = compareMountAnchors(
                prefix = "Cross-process",
                mainNamespace = nativeSnapshot.mountNamespaceInode,
                mainApex = nativeSnapshot.apexMountKey,
                mainSystem = nativeSnapshot.systemMountKey,
                mainVendor = nativeSnapshot.vendorMountKey,
                otherNamespace = remoteSnapshot.mountNamespaceInode,
                otherApex = remoteSnapshot.apexMountKey,
                otherSystem = remoteSnapshot.systemMountKey,
                otherVendor = remoteSnapshot.vendorMountKey,
                severity = VirtualizationSignalSeverity.DANGER,
            )
            crossSignals += regularAnchorResult.crossProcessSignals
            mountAnchorDriftCount += regularAnchorResult.mountAnchorDriftCount
        }

        if (isolatedSnapshot.available) {
            val isolatedAnchorResult = compareMountAnchors(
                prefix = "Isolated",
                mainNamespace = nativeSnapshot.mountNamespaceInode,
                mainApex = nativeSnapshot.apexMountKey,
                mainSystem = nativeSnapshot.systemMountKey,
                mainVendor = nativeSnapshot.vendorMountKey,
                otherNamespace = isolatedSnapshot.mountNamespaceInode,
                otherApex = isolatedSnapshot.apexMountKey,
                otherSystem = isolatedSnapshot.systemMountKey,
                otherVendor = isolatedSnapshot.vendorMountKey,
                severity = VirtualizationSignalSeverity.DANGER,
            )
            isolatedSignals += isolatedAnchorResult.crossProcessSignals
            mountAnchorDriftCount += isolatedAnchorResult.mountAnchorDriftCount
        }

        if (preloadResult.hasRun) {
            val preloadAnchorResult = compareMountAnchors(
                prefix = "Startup/runtime",
                mainNamespace = preloadResult.mountNamespaceInode,
                mainApex = preloadResult.apexMountKey,
                mainSystem = preloadResult.systemMountKey,
                mainVendor = preloadResult.vendorMountKey,
                otherNamespace = nativeSnapshot.mountNamespaceInode,
                otherApex = nativeSnapshot.apexMountKey,
                otherSystem = nativeSnapshot.systemMountKey,
                otherVendor = nativeSnapshot.vendorMountKey,
                severity = VirtualizationSignalSeverity.WARNING,
            )
            crossSignals += preloadAnchorResult.crossProcessSignals
            mountAnchorDriftCount += preloadAnchorResult.mountAnchorDriftCount
        }

        return ConsistencyComputation(
            crossProcessSignals = crossSignals.distinctBy { it.id },
            isolatedSignals = isolatedSignals.distinctBy { it.id },
            mountAnchorDriftCount = mountAnchorDriftCount,
        )
    }

    private fun compareMountAnchors(
        prefix: String,
        mainNamespace: String,
        mainApex: String,
        mainSystem: String,
        mainVendor: String,
        otherNamespace: String,
        otherApex: String,
        otherSystem: String,
        otherVendor: String,
        severity: VirtualizationSignalSeverity,
    ): ConsistencyComputation {
        if (
            mainNamespace.isBlank() &&
            mainApex.isBlank() &&
            mainSystem.isBlank() &&
            mainVendor.isBlank()
        ) {
            return ConsistencyComputation()
        }

        val driftLines = buildList {
            compareSingleMountAnchor("/apex", mainApex, otherApex)?.let(::add)
            compareSingleMountAnchor("/system", mainSystem, otherSystem)?.let(::add)
            compareSingleMountAnchor("/vendor", mainVendor, otherVendor)?.let(::add)
        }
        val comparableAnchorCount = listOf(
            mainApex to otherApex,
            mainSystem to otherSystem,
            mainVendor to otherVendor,
        ).count { (mainRaw, otherRaw) -> hasComparableMountAnchors(mainRaw, otherRaw) }
        val namespaceDrift = mainNamespace.isNotBlank() &&
                otherNamespace.isNotBlank() &&
                mainNamespace != otherNamespace
        val signals = mutableListOf<VirtualizationSignal>()

        if (driftLines.isNotEmpty()) {
            signals += VirtualizationSignal(
                id = "virt_mount_drift_${prefix.lowercase().replace(" ", "_")}",
                label = "$prefix mount anchor drift",
                value = "Danger",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = severity,
                detail = driftLines.joinToString(separator = "\n"),
                detailMonospace = true,
            )
        } else if (namespaceDrift && comparableAnchorCount == 0) {
            signals += VirtualizationSignal(
                id = "virt_namespace_drift_${prefix.lowercase().replace(" ", "_")}",
                label = "$prefix namespace drift",
                value = "Review",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = "mnt namespace main=$mainNamespace other=$otherNamespace",
                detailMonospace = true,
            )
        }

        return ConsistencyComputation(
            crossProcessSignals = signals,
            mountAnchorDriftCount = driftLines.size,
        )
    }

    private fun compareSingleMountAnchor(
        label: String,
        mainRaw: String,
        otherRaw: String,
    ): String? {
        if (mainRaw.isBlank() && otherRaw.isBlank()) {
            return null
        }
        if (mainRaw.isBlank() || otherRaw.isBlank()) {
            return "$label main=${mainRaw.ifBlank { "<missing>" }} other=${otherRaw.ifBlank { "<missing>" }}"
        }

        val mainAnchor = ParsedMountAnchor.parse(mainRaw) ?: return null
        val otherAnchor = ParsedMountAnchor.parse(otherRaw) ?: return null
        if (mainAnchor.semanticKey == otherAnchor.semanticKey) {
            return null
        }
        return "$label main=${mainAnchor.semanticSummary()} other=${otherAnchor.semanticSummary()}"
    }

    private fun hasComparableMountAnchors(
        mainRaw: String,
        otherRaw: String,
    ): Boolean {
        return ParsedMountAnchor.parse(mainRaw) != null && ParsedMountAnchor.parse(otherRaw) != null
    }

    private fun comparableArtifactKeys(
        findings: List<VirtualizationNativeFinding>,
    ): Set<String> {
        return findings.asSequence()
            .filterNot { it.severity.equals("INFO", ignoreCase = true) }
            .filterNot { it.label.equals("Graphics renderer", ignoreCase = true) }
            .map { "${it.group}:${it.label}:${it.value}" }
            .toCollection(linkedSetOf())
    }

    internal fun buildHostAppSignals(result: VirtualizationHostAppProbeResult): List<VirtualizationSignal> {
        return result.findings.map { finding ->
            VirtualizationSignal(
                id = "virt_host_${finding.target.packageName}",
                label = finding.target.appName,
                value = "Corroboration",
                group = VirtualizationSignalGroup.HOST_APPS,
                severity = VirtualizationSignalSeverity.INFO,
                detail = finding.methods.joinToString(separator = "\n") { method ->
                    method.detail?.let { "${method.kind.label}: $it" } ?: method.kind.label
                },
                detailMonospace = true,
            )
        }
    }

    internal fun buildHoneypotSignals(
        nativeTimingTrap: VirtualizationTrapResult,
        nativeSyscallParityTrap: VirtualizationTrapResult,
        asmCounterTrap: VirtualizationTrapResult,
        asmRawSyscallTrap: VirtualizationTrapResult,
        syscallPackResult: SacrificialSyscallPackResult,
    ): List<VirtualizationSignal> = buildList {
        addTrapSignal("Native timing trap", "virt_trap_native_timing", nativeTimingTrap)
        addTrapSignal(
            "Native syscall parity trap",
            "virt_trap_native_syscall_parity",
            nativeSyscallParityTrap,
        )
        addTrapSignal("ASM counter trap", "virt_trap_asm_counter", asmCounterTrap)
        addTrapSignal("ASM raw syscall trap", "virt_trap_asm_syscall", asmRawSyscallTrap)
        syscallPackResult.suspiciousItems.forEach { item ->
            add(
                VirtualizationSignal(
                    id = "virt_trap_pack_${item.label.lowercase().replace(' ', '_')}",
                    label = "Sacrificial ${item.label}",
                    value = "${item.suspiciousAttempts}/${item.completedAttempts}",
                    group = VirtualizationSignalGroup.HONEYPOT,
                    severity = VirtualizationSignalSeverity.WARNING,
                    detail = item.detail.ifBlank {
                        item.attempts.joinToString(separator = "\n") { attempt -> attempt.detail }
                    },
                    detailMonospace = true,
                ),
            )
        }
    }

    private fun MutableList<VirtualizationSignal>.addTrapSignal(
        label: String,
        id: String,
        result: VirtualizationTrapResult,
    ) {
        if (!result.suspicious) return
        add(
            VirtualizationSignal(
                id = id,
                label = label,
                value = "${result.suspiciousAttempts}/${result.completedAttempts}",
                group = VirtualizationSignalGroup.HONEYPOT,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = result.detail,
                detailMonospace = true,
            ),
        )
    }

    internal fun buildMethods(
        propertySignals: List<VirtualizationSignal>,
        dexPathResult: DexPathProbeResult,
        uidIdentityResult: UidIdentityProbeResult,
        runtimeSignals: List<VirtualizationSignal>,
        graphicsSignals: List<VirtualizationSignal>,
        translationSignals: List<VirtualizationSignal>,
        preloadSignals: List<VirtualizationSignal>,
        preloadResult: EarlyVirtualizationPreloadResult,
        crossProcessSignals: List<VirtualizationSignal>,
        isolatedSignals: List<VirtualizationSignal>,
        remoteSnapshot: VirtualizationRemoteSnapshot,
        isolatedSnapshot: VirtualizationRemoteSnapshot,
        hostAppResult: VirtualizationHostAppProbeResult,
        nativeTimingTrap: VirtualizationTrapResult,
        nativeSyscallParityTrap: VirtualizationTrapResult,
        asmCounterTrap: VirtualizationTrapResult,
        asmRawSyscallTrap: VirtualizationTrapResult,
        syscallPackResult: SacrificialSyscallPackResult,
        listedServiceCount: Int,
    ): List<VirtualizationMethodResult> {
        val nativeTrapResults = listOf(nativeTimingTrap, nativeSyscallParityTrap)
        val asmTrapResults = listOf(asmCounterTrap, asmRawSyscallTrap)
        return listOf(
            VirtualizationMethodResult(
                label = "Properties and build",
                summary = methodSummary(propertySignals),
                outcome = methodOutcome(propertySignals),
                detail = "Checks system properties, Build fields, and ServiceManager guest services.\nListed services: $listedServiceCount",
            ),
            VirtualizationMethodResult(
                label = "Dex and classpath",
                summary = if (dexPathResult.signals.isEmpty()) "Clean" else methodSummary(
                    dexPathResult.signals
                ),
                outcome = methodOutcome(dexPathResult.signals),
                detail = buildString {
                    append("Class path entries: ")
                    append(dexPathResult.entryCount)
                    if (dexPathResult.classPathEntries.isNotEmpty()) {
                        append("\n")
                        append(dexPathResult.classPathEntries.joinToString(separator = "\n"))
                    }
                },
            ),
            VirtualizationMethodResult(
                label = "UID identity",
                summary = if (uidIdentityResult.signals.isEmpty()) "Clean" else methodSummary(
                    uidIdentityResult.signals
                ),
                outcome = methodOutcome(uidIdentityResult.signals),
                detail = buildString {
                    append("uid=")
                    append(uidIdentityResult.uid)
                    append(" applicationUid=")
                    append(uidIdentityResult.applicationUid)
                    append("\nprocessName=")
                    append(uidIdentityResult.processName)
                    append("\nuidName=")
                    append(uidIdentityResult.uidName.ifBlank { "<empty>" })
                    append("\npackagesForUid=\n")
                    append(
                        uidIdentityResult.packagesForUid.joinToString(separator = "\n")
                            .ifBlank { "<empty>" })
                },
            ),
            VirtualizationMethodResult(
                label = "Runtime artifacts",
                summary = if (runtimeSignals.isEmpty()) "Clean" else methodSummary(runtimeSignals),
                outcome = if (runtimeSignals.isEmpty()) VirtualizationMethodOutcome.CLEAN else methodOutcome(
                    runtimeSignals
                ),
                detail = "Collects /proc/self/maps, /proc/self/fd, mountinfo, direct device nodes, and raw mount anchors from the current process.",
            ),
            VirtualizationMethodResult(
                label = "Graphics renderer",
                summary = if (graphicsSignals.isEmpty()) "Clean" else methodSummary(graphicsSignals),
                outcome = if (graphicsSignals.isEmpty()) VirtualizationMethodOutcome.CLEAN else methodOutcome(
                    graphicsSignals
                ),
                detail = "Builds an off-screen EGL context and inspects GL_VENDOR, GL_RENDERER, and GL_VERSION.",
            ),
            VirtualizationMethodResult(
                label = "Native bridge",
                summary = methodSummary(translationSignals),
                outcome = methodOutcome(translationSignals),
                detail = "Checks ART native bridge properties and translated runtime libraries such as libhoudini, libnb, and libndk_translation.",
            ),
            VirtualizationMethodResult(
                label = "Startup preload",
                summary = when {
                    !preloadResult.hasRun -> "Unavailable"
                    preloadSignals.isEmpty() -> "Clean"
                    else -> methodSummary(preloadSignals)
                },
                outcome = when {
                    !preloadResult.hasRun -> VirtualizationMethodOutcome.SUPPORT
                    preloadSignals.isEmpty() -> VirtualizationMethodOutcome.CLEAN
                    else -> methodOutcome(preloadSignals)
                },
                detail = preloadResult.details,
            ),
            VirtualizationMethodResult(
                label = "Cross-process consistency",
                summary = when {
                    !remoteSnapshot.available -> "Unavailable"
                    crossProcessSignals.isEmpty() -> "Clean"
                    else -> "${crossProcessSignals.size} drift hit(s)"
                },
                outcome = when {
                    !remoteSnapshot.available -> VirtualizationMethodOutcome.SUPPORT
                    crossProcessSignals.isEmpty() -> VirtualizationMethodOutcome.CLEAN
                    else -> methodOutcome(crossProcessSignals)
                },
                detail = remoteSnapshot.errorDetail.ifBlank {
                    "Compares regular helper-process paths, mount anchors, and artifact sets against the main process and startup preload."
                },
            ),
            VirtualizationMethodResult(
                label = "Isolated-process consistency",
                summary = when {
                    !isolatedSnapshot.available -> "Unavailable"
                    isolatedSignals.isEmpty() -> "Clean"
                    else -> "${isolatedSignals.size} drift hit(s)"
                },
                outcome = when {
                    !isolatedSnapshot.available -> VirtualizationMethodOutcome.SUPPORT
                    isolatedSignals.isEmpty() -> VirtualizationMethodOutcome.CLEAN
                    else -> methodOutcome(isolatedSignals)
                },
                detail = isolatedSnapshot.errorDetail.ifBlank {
                    "Compares the isolated process against the main process for host residue, namespace drift, and anchor-mount divergence."
                },
            ),
            VirtualizationMethodResult(
                label = "Host apps",
                summary = when {
                    hostAppResult.findings.isNotEmpty() -> "${hostAppResult.findings.size} corroborating app(s)"
                    hostAppResult.packageVisibility == InstalledPackageVisibility.RESTRICTED -> "Scoped"
                    else -> "Clean"
                },
                outcome = when {
                    hostAppResult.findings.isNotEmpty() -> VirtualizationMethodOutcome.INFO
                    hostAppResult.packageVisibility == InstalledPackageVisibility.RESTRICTED -> VirtualizationMethodOutcome.SUPPORT
                    else -> VirtualizationMethodOutcome.CLEAN
                },
                detail = hostAppResult.issues.joinToString(separator = "\n").ifBlank {
                    "Checks known virtualization host packages via PackageManager, FUSE paths, native /data stats, and special paths."
                },
            ),
            VirtualizationMethodResult(
                label = "Native honeypots",
                summary = honeypotSummary(nativeTrapResults),
                outcome = honeypotOutcome(nativeTrapResults),
                detail = listOf(nativeTimingTrap.detail, nativeSyscallParityTrap.detail)
                    .filter { it.isNotBlank() }
                    .joinToString(separator = "\n\n"),
            ),
            VirtualizationMethodResult(
                label = "ASM honeypots",
                summary = honeypotSummary(asmTrapResults),
                outcome = honeypotOutcome(asmTrapResults),
                detail = listOf(asmCounterTrap.detail, asmRawSyscallTrap.detail)
                    .filter { it.isNotBlank() }
                    .joinToString(separator = "\n\n"),
            ),
            VirtualizationMethodResult(
                label = "Sacrificial syscall pack",
                summary = syscallPackSummary(syscallPackResult),
                outcome = syscallPackOutcome(syscallPackResult),
                detail = buildString {
                    append(syscallPackResult.detail)
                    if (syscallPackResult.items.isNotEmpty()) {
                        if (isNotEmpty()) append("\n\n")
                        append(
                            syscallPackResult.items.joinToString(separator = "\n\n") { item ->
                                buildString {
                                    append(item.label)
                                    append(": ")
                                    append(item.suspiciousAttempts)
                                    append("/")
                                    append(item.completedAttempts)
                                    append(" suspicious")
                                    if (item.detail.isNotBlank()) {
                                        append("\n")
                                        append(item.detail)
                                    }
                                }
                            },
                        )
                    }
                }.trim(),
            ),
        )
    }

    internal fun buildImpacts(
        signals: List<VirtualizationSignal>,
        hostAppResult: VirtualizationHostAppProbeResult,
    ): List<VirtualizationImpact> {
        if (signals.isEmpty()) {
            return listOf(
                VirtualizationImpact(
                    text = "No direct emulator, AVF guest, translation, classpath, or consistency drift signal surfaced from the current app context.",
                    severity = VirtualizationSignalSeverity.SAFE,
                ),
            )
        }
        if (
            signals.none {
                it.severity == VirtualizationSignalSeverity.DANGER ||
                        it.severity == VirtualizationSignalSeverity.WARNING
            } &&
            hostAppResult.findings.isNotEmpty()
        ) {
            return listOf(
                VirtualizationImpact(
                    text = "Known virtualization host apps are installed, but current process probes did not confirm guest or translated execution.",
                    severity = VirtualizationSignalSeverity.INFO,
                ),
            )
        }
        return signals.take(5).map { signal ->
            VirtualizationImpact(
                text = buildString {
                    append(signal.label)
                    signal.detail?.takeIf { it.isNotBlank() }?.let { detail ->
                        append(": ")
                        append(detail.lineSequence().firstOrNull().orEmpty())
                    }
                },
                severity = signal.severity,
            )
        }
    }

    private fun methodSummary(signals: List<VirtualizationSignal>): String {
        return when {
            signals.any { it.severity == VirtualizationSignalSeverity.DANGER } -> "${signals.size} hit(s)"
            signals.any { it.severity == VirtualizationSignalSeverity.WARNING } -> "${signals.size} hit(s)"
            signals.any { it.severity == VirtualizationSignalSeverity.INFO } -> "${signals.size} info hit(s)"
            else -> "Clean"
        }
    }

    private fun methodOutcome(signals: List<VirtualizationSignal>): VirtualizationMethodOutcome {
        return when {
            signals.any { it.severity == VirtualizationSignalSeverity.DANGER } -> VirtualizationMethodOutcome.DANGER
            signals.any { it.severity == VirtualizationSignalSeverity.WARNING } -> VirtualizationMethodOutcome.WARNING
            signals.any { it.severity == VirtualizationSignalSeverity.INFO } -> VirtualizationMethodOutcome.INFO
            else -> VirtualizationMethodOutcome.CLEAN
        }
    }

    private fun honeypotSummary(results: List<VirtualizationTrapResult>): String {
        val supported = results.filter { it.supported }
        return when {
            supported.isEmpty() -> "Unsupported"
            supported.any { it.suspicious } -> "${supported.count { it.suspicious }} suspicious trap(s)"
            supported.all { it.clean } -> "Clean"
            else -> "Partial"
        }
    }

    private fun honeypotOutcome(results: List<VirtualizationTrapResult>): VirtualizationMethodOutcome {
        val supported = results.filter { it.supported }
        return when {
            supported.isEmpty() -> VirtualizationMethodOutcome.SUPPORT
            supported.any { it.suspicious } -> VirtualizationMethodOutcome.WARNING
            supported.all { it.clean } -> VirtualizationMethodOutcome.CLEAN
            else -> VirtualizationMethodOutcome.SUPPORT
        }
    }

    private fun syscallPackSummary(result: SacrificialSyscallPackResult): String {
        return when {
            !result.supported -> "Unsupported"
            result.suspiciousItems.isNotEmpty() -> "${result.suspiciousItems.size} suspicious syscall(s)"
            result.items.isNotEmpty() && result.items.all { it.clean } -> "Clean"
            else -> "Partial"
        }
    }

    private fun syscallPackOutcome(result: SacrificialSyscallPackResult): VirtualizationMethodOutcome {
        return when {
            !result.supported -> VirtualizationMethodOutcome.SUPPORT
            result.suspiciousItems.isNotEmpty() -> VirtualizationMethodOutcome.WARNING
            result.items.isNotEmpty() && result.items.all { it.clean } -> VirtualizationMethodOutcome.CLEAN
            else -> VirtualizationMethodOutcome.SUPPORT
        }
    }

    private fun severityPriority(severity: VirtualizationSignalSeverity): Int {
        return when (severity) {
            VirtualizationSignalSeverity.DANGER -> 0
            VirtualizationSignalSeverity.WARNING -> 1
            VirtualizationSignalSeverity.INFO -> 2
            VirtualizationSignalSeverity.SAFE -> 3
        }
    }

    private fun groupPriority(group: VirtualizationSignalGroup): Int {
        return when (group) {
            VirtualizationSignalGroup.ENVIRONMENT -> 0
            VirtualizationSignalGroup.TRANSLATION -> 1
            VirtualizationSignalGroup.RUNTIME -> 2
            VirtualizationSignalGroup.CONSISTENCY -> 3
            VirtualizationSignalGroup.HONEYPOT -> 4
            VirtualizationSignalGroup.HOST_APPS -> 5
        }
    }

    private fun String?.shouldUseMonospace(): Boolean {
        val value = this.orEmpty()
        return value.contains("/proc/") ||
                value.contains("/data/") ||
                value.contains("/dev/") ||
                value.contains(".so") ||
                value.contains("=") ||
                value.contains(":") ||
                value.contains("|")
    }
}
