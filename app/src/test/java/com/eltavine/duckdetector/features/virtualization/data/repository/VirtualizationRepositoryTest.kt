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

import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.startup.preload.EarlyVirtualizationPreloadResult
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
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppFinding
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostAppProbeResult
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostDetectionMethod
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationHostDetectionMethodKind
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationPropertyProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.VirtualizationServiceProbeResult
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppTarget
import com.eltavine.duckdetector.features.virtualization.data.service.VirtualizationIsolatedProbeManager
import com.eltavine.duckdetector.features.virtualization.data.service.VirtualizationProbeManager
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationMethodOutcome
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VirtualizationRepositoryTest {

    @Test
    fun `classic emulator strong props and runtime hits map to danger`() = runBlocking {
        val report = repository(
            propertySignals = listOf(
                signal(
                    "prop",
                    "ro.kernel.qemu",
                    VirtualizationSignalGroup.ENVIRONMENT,
                    VirtualizationSignalSeverity.DANGER
                ),
            ),
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                findings = listOf(
                    VirtualizationNativeFinding(
                        "RUNTIME",
                        "DANGER",
                        "Emulator device node",
                        "/dev/qemu_pipe",
                        "/dev/qemu_pipe"
                    ),
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isNotEmpty())
        assertEquals(1, report.environmentHitCount)
        assertTrue(report.runtimeArtifactHitCount > 0)
    }

    @Test
    fun `translation only maps to warning`() = runBlocking {
        val report = repository(
            propertySignals = listOf(
                signal(
                    "bridge",
                    "ro.dalvik.vm.native.bridge",
                    VirtualizationSignalGroup.TRANSLATION,
                    VirtualizationSignalSeverity.WARNING
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertEquals(1, report.warningSignals.size)
        assertEquals(1, report.translationHitCount)
    }

    @Test
    fun `host apps only remain corroboration only`() = runBlocking {
        val report = repository(
            hostAppResult = VirtualizationHostAppProbeResult(
                packageVisibility = InstalledPackageVisibility.FULL,
                findings = listOf(
                    VirtualizationHostAppFinding(
                        target = VirtualizationHostAppTarget("com.vmos.pro", "VMOS Pro"),
                        methods = listOf(
                            VirtualizationHostDetectionMethod(
                                VirtualizationHostDetectionMethodKind.PACKAGE_MANAGER,
                            ),
                        ),
                    ),
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertTrue(report.warningSignals.isEmpty())
        assertTrue(report.onlyHostAppCorroboration)
        assertEquals(1, report.hostAppCorroborationCount)
        assertEquals(
            VirtualizationMethodOutcome.INFO,
            report.methods.first { it.label == "Host apps" }.outcome,
        )
    }

    @Test
    fun `capability only signal does not count as detection`() = runBlocking {
        val report = repository(
            propertySignals = listOf(
                signal(
                    "cap",
                    "Hypervisor capability",
                    VirtualizationSignalGroup.ENVIRONMENT,
                    VirtualizationSignalSeverity.INFO
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertTrue(report.warningSignals.isEmpty())
        assertFalse(report.onlyHostAppCorroboration)
    }

    @Test
    fun `preload only strong evidence enters report`() = runBlocking {
        val report = repository(
            preloadResult = EarlyVirtualizationPreloadResult(
                hasRun = true,
                detected = true,
                qemuPropertyDetected = true,
                details = "preload",
            ).normalize(),
        ).scanInternal()

        assertTrue(report.startupPreloadAvailable)
        assertTrue(report.dangerSignals.any { it.id.contains("preload") })
    }

    @Test
    fun `main and helper drift create consistency hit`() = runBlocking {
        val report = repository(
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                findings = listOf(
                    VirtualizationNativeFinding(
                        "RUNTIME",
                        "DANGER",
                        "Emulator device node",
                        "/dev/qemu_pipe",
                        "/dev/qemu_pipe"
                    ),
                ),
            ),
            remoteSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                nativeAvailable = true,
                filesDir = "/data/user/0/com.eltavine.duckdetector.virtual",
                cacheDir = "/data/user/0/com.eltavine.duckdetector.virtual/cache",
                codePath = "/data/app/virtual/base.apk",
                findings = emptyList(),
            ),
            processInfo = VirtualizationProcessInfo(
                filesDir = "/data/user/0/com.eltavine.duckdetector/files",
                cacheDir = "/data/user/0/com.eltavine.duckdetector/cache",
                codePath = "/data/app/normal/base.apk",
            ),
        ).scanInternal()

        assertTrue(report.consistencyHitCount > 0)
        assertTrue(report.consistencyRows.any { it.label.contains("drift", ignoreCase = true) })
    }

    @Test
    fun `graphics only artifact difference does not trigger cross process artifact drift`() =
        runBlocking {
            val report = repository(
                nativeSnapshot = VirtualizationNativeSnapshot(
                    available = true,
                    findings = listOf(
                        VirtualizationNativeFinding(
                            "RUNTIME",
                            "WARNING",
                            "Graphics renderer",
                            "gfxstream",
                            "Google\ngfxstream\nOpenGL ES 3.2",
                        ),
                    ),
                ),
                remoteSnapshot = VirtualizationRemoteSnapshot(
                    available = true,
                    profile = VirtualizationRemoteProfile.REGULAR,
                    findings = emptyList(),
                ),
            ).scanInternal()

            assertTrue(report.consistencyRows.none { it.label == "Cross-process artifact drift" })
        }

    @Test
    fun `host classpath residue maps to danger`() = runBlocking {
        val report = repository(
            dexPathResult = DexPathProbeResult(
                classPathEntries = listOf(
                    "/data/app/com.vmos.pro/base.apk",
                    "/data/app/com.eltavine.duckdetector/base.apk",
                ),
                entryCount = 2,
                hitCount = 1,
                hostPathHit = true,
                signals = listOf(
                    signal(
                        id = "dex_host",
                        label = "Host dex path",
                        group = VirtualizationSignalGroup.RUNTIME,
                        severity = VirtualizationSignalSeverity.DANGER,
                    ),
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.any { it.label == "Host dex path" })
        assertEquals(1, report.dexPathHitCount)
    }

    @Test
    fun `egl renderer alone stays warning`() = runBlocking {
        val report = repository(
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                eglAvailable = true,
                eglRenderer = "gfxstream",
                findings = listOf(
                    VirtualizationNativeFinding(
                        "RUNTIME",
                        "WARNING",
                        "Graphics renderer",
                        "gfxstream",
                        "Google\ngfxstream\nOpenGL ES 3.2",
                    ),
                ),
            ),
        ).scanInternal()

        assertTrue(report.dangerSignals.isEmpty())
        assertTrue(report.warningSignals.any { it.label == "Graphics renderer" })
        assertEquals(
            VirtualizationMethodOutcome.WARNING,
            report.methods.first { it.label == "Graphics renderer" }.outcome,
        )
    }

    @Test
    fun `main helper contaminated while isolated stays clean maps to danger`() = runBlocking {
        val report = repository(
            remoteSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.REGULAR,
                classPathEntries = listOf("/data/app/com.vmos.pro/base.apk"),
            ),
            isolatedSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.ISOLATED,
                classPathEntries = emptyList(),
                packagesForUid = emptyList(),
            ),
        ).scanInternal()

        assertTrue(
            report.consistencyRows.any {
                it.label == "Isolated process stayed clean" &&
                        it.severity == VirtualizationSignalSeverity.DANGER
            },
        )
    }

    @Test
    fun `mount anchor drift maps to danger`() = runBlocking {
        val report = repository(
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                mountNamespaceInode = "mnt:[1]",
                apexMountKey = "10|8:1|/|/apex|ext4|/dev/block/dm-1",
            ),
            remoteSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.REGULAR,
                mountNamespaceInode = "mnt:[2]",
                apexMountKey = "11|8:1|/|/apex|authfs|microdroid",
            ),
        ).scanInternal()

        assertEquals(1, report.mountAnchorDriftCount)
        assertTrue(
            report.consistencyRows.any {
                it.label == "Cross-process mount anchor drift" &&
                        it.severity == VirtualizationSignalSeverity.DANGER
            },
        )
    }

    @Test
    fun `mount id only difference does not create anchor drift`() = runBlocking {
        val report = repository(
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                mountNamespaceInode = "mnt:[1]",
                apexMountKey = "10|0:22|/|/apex|tmpfs|tmpfs",
                vendorMountKey = "20|254:29|/|/vendor|erofs|/dev/block/dm-29",
            ),
            remoteSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.REGULAR,
                mountNamespaceInode = "mnt:[2]",
                apexMountKey = "99|0:22|/|/apex|tmpfs|tmpfs",
                vendorMountKey = "88|254:29|/|/vendor|erofs|/dev/block/dm-29",
            ),
        ).scanInternal()

        assertEquals(0, report.mountAnchorDriftCount)
        assertTrue(report.consistencyRows.none { it.label == "Cross-process mount anchor drift" })
        assertTrue(report.consistencyRows.none { it.label == "Cross-process namespace drift" })
    }

    @Test
    fun `namespace drift without comparable anchors stays warning`() = runBlocking {
        val report = repository(
            nativeSnapshot = VirtualizationNativeSnapshot(
                available = true,
                mountNamespaceInode = "mnt:[1]",
            ),
            remoteSnapshot = VirtualizationRemoteSnapshot(
                available = true,
                profile = VirtualizationRemoteProfile.REGULAR,
                mountNamespaceInode = "mnt:[2]",
            ),
        ).scanInternal()

        assertEquals(0, report.mountAnchorDriftCount)
        assertTrue(
            report.consistencyRows.any {
                it.label == "Cross-process namespace drift" &&
                        it.severity == VirtualizationSignalSeverity.WARNING
            },
        )
    }

    @Test
    fun `syscall pack suspicious item adds honeypot warning`() = runBlocking {
        val report = repository(
            syscallPackResult = SacrificialSyscallPackResult(
                available = true,
                supported = true,
                items = listOf(
                    com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationSyscallPackItem(
                        label = "openat2",
                        supported = true,
                        completedAttempts = 3,
                        suspiciousAttempts = 2,
                        detail = "libc/raw/asm mismatch",
                    ),
                ),
            ),
        ).scanInternal()

        assertEquals(1, report.syscallPackHitCount)
        assertTrue(report.honeypotRows.any { it.label == "Sacrificial openat2" })
        assertEquals(
            VirtualizationMethodOutcome.WARNING,
            report.methods.first { it.label == "Sacrificial syscall pack" }.outcome,
        )
    }

    @Test
    fun `unsupported syscall pack stays support`() = runBlocking {
        val report = repository(
            syscallPackResult = SacrificialSyscallPackResult(
                available = true,
                supported = false,
                detail = "SIGSYS disabled the pack",
            ),
        ).scanInternal()

        assertEquals(0, report.syscallPackHitCount)
        assertEquals(
            VirtualizationMethodOutcome.SUPPORT,
            report.methods.first { it.label == "Sacrificial syscall pack" }.outcome,
        )
    }

    private fun repository(
        propertySignals: List<VirtualizationSignal> = emptyList(),
        buildSignals: List<VirtualizationSignal> = emptyList(),
        serviceResult: VirtualizationServiceProbeResult = VirtualizationServiceProbeResult(
            0,
            emptyList()
        ),
        dexPathResult: DexPathProbeResult = DexPathProbeResult(),
        uidIdentityResult: UidIdentityProbeResult = UidIdentityProbeResult(),
        nativeSnapshot: VirtualizationNativeSnapshot = VirtualizationNativeSnapshot(available = true),
        preloadResult: EarlyVirtualizationPreloadResult = EarlyVirtualizationPreloadResult.empty(),
        remoteSnapshot: VirtualizationRemoteSnapshot = VirtualizationRemoteSnapshot(),
        isolatedSnapshot: VirtualizationRemoteSnapshot = VirtualizationRemoteSnapshot(
            profile = VirtualizationRemoteProfile.ISOLATED,
        ),
        hostAppResult: VirtualizationHostAppProbeResult = VirtualizationHostAppProbeResult(
            packageVisibility = InstalledPackageVisibility.FULL,
            findings = emptyList(),
        ),
        processInfo: VirtualizationProcessInfo = VirtualizationProcessInfo(),
        syscallPackResult: SacrificialSyscallPackResult = SacrificialSyscallPackResult(),
    ): VirtualizationRepository {
        return VirtualizationRepository(
            propertyProbe = object : VirtualizationPropertyProbe() {
                override fun probe(): List<VirtualizationSignal> = propertySignals
            },
            buildProbe = object : VirtualizationBuildProbe() {
                override fun probe(): List<VirtualizationSignal> = buildSignals
            },
            serviceProbe = object : VirtualizationServiceProbe() {
                override fun probe(): VirtualizationServiceProbeResult = serviceResult
            },
            dexPathProbe = object : DexPathProbe() {
                override fun probe(): DexPathProbeResult = dexPathResult
            },
            uidIdentityProbe = object : UidIdentityProbe() {
                override fun probe(): UidIdentityProbeResult = uidIdentityResult
            },
            nativeBridge = object : VirtualizationNativeBridge() {
                override fun collectSnapshot(): VirtualizationNativeSnapshot = nativeSnapshot
            },
            hostAppProbe = object : VirtualizationHostAppProbe() {
                override fun probe(): VirtualizationHostAppProbeResult = hostAppResult
            },
            probeManager = object : VirtualizationProbeManager() {
                override suspend fun collect(): VirtualizationRemoteSnapshot = remoteSnapshot
                override suspend fun runSacrificialSyscallPack(): SacrificialSyscallPackResult =
                    syscallPackResult
            },
            isolatedProbeManager = object : VirtualizationIsolatedProbeManager() {
                override suspend fun collect(): VirtualizationRemoteSnapshot = isolatedSnapshot
            },
            nativeTimingTrapProbe = object : NativeTimingTrapProbe() {
                override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
            },
            nativeSyscallParityTrapProbe = object : NativeSyscallParityTrapProbe() {
                override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
            },
            asmCounterTrapProbe = object : AsmCounterTrapProbe() {
                override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
            },
            asmRawSyscallTrapProbe = object : AsmRawSyscallTrapProbe() {
                override fun probe(): VirtualizationTrapResult = VirtualizationTrapResult()
            },
            preloadResultProvider = { preloadResult },
            processInfoProvider = { processInfo },
        )
    }

    private fun signal(
        id: String,
        label: String,
        group: VirtualizationSignalGroup,
        severity: VirtualizationSignalSeverity,
    ): VirtualizationSignal {
        return VirtualizationSignal(
            id = id,
            label = label,
            value = label,
            group = group,
            severity = severity,
            detail = label,
        )
    }
}
