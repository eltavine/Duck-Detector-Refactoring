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

package com.eltavine.duckdetector.features.virtualization.domain

import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility

enum class VirtualizationStage {
    LOADING,
    READY,
    FAILED,
}

enum class VirtualizationSignalGroup {
    ENVIRONMENT,
    TRANSLATION,
    RUNTIME,
    CONSISTENCY,
    HONEYPOT,
    HOST_APPS,
}

enum class VirtualizationSignalSeverity {
    INFO,
    SAFE,
    WARNING,
    DANGER,
}

enum class VirtualizationMethodOutcome {
    CLEAN,
    INFO,
    WARNING,
    DANGER,
    SUPPORT,
}

data class VirtualizationSignal(
    val id: String,
    val label: String,
    val value: String,
    val group: VirtualizationSignalGroup,
    val severity: VirtualizationSignalSeverity,
    val detail: String? = null,
    val detailMonospace: Boolean = false,
)

data class VirtualizationMethodResult(
    val label: String,
    val summary: String,
    val outcome: VirtualizationMethodOutcome,
    val detail: String? = null,
)

data class VirtualizationImpact(
    val text: String,
    val severity: VirtualizationSignalSeverity,
)

data class VirtualizationReport(
    val stage: VirtualizationStage,
    val nativeAvailable: Boolean,
    val startupPreloadAvailable: Boolean,
    val startupPreloadContextValid: Boolean,
    val crossProcessAvailable: Boolean,
    val isolatedProcessAvailable: Boolean,
    val asmSupported: Boolean,
    val eglAvailable: Boolean,
    val packageVisibility: InstalledPackageVisibility,
    val dexPathEntryCount: Int,
    val dexPathHitCount: Int,
    val uidIdentityHitCount: Int,
    val environmentHitCount: Int,
    val translationHitCount: Int,
    val runtimeArtifactHitCount: Int,
    val consistencyHitCount: Int,
    val isolatedConsistencyHitCount: Int,
    val mountAnchorDriftCount: Int,
    val mountNamespaceAvailable: Boolean,
    val honeypotHitCount: Int,
    val syscallPackSupported: Boolean,
    val syscallPackHitCount: Int,
    val hostAppCorroborationCount: Int,
    val mapLineCount: Int,
    val fdCount: Int,
    val mountInfoCount: Int,
    val signals: List<VirtualizationSignal>,
    val methods: List<VirtualizationMethodResult>,
    val impacts: List<VirtualizationImpact>,
    val errorMessage: String? = null,
) {
    val environmentRows: List<VirtualizationSignal>
        get() = signals.filter {
            it.group == VirtualizationSignalGroup.ENVIRONMENT ||
                    it.group == VirtualizationSignalGroup.TRANSLATION
        }

    val runtimeRows: List<VirtualizationSignal>
        get() = signals.filter { it.group == VirtualizationSignalGroup.RUNTIME }

    val consistencyRows: List<VirtualizationSignal>
        get() = signals.filter { it.group == VirtualizationSignalGroup.CONSISTENCY }

    val honeypotRows: List<VirtualizationSignal>
        get() = signals.filter { it.group == VirtualizationSignalGroup.HONEYPOT }

    val hostAppRows: List<VirtualizationSignal>
        get() = signals.filter { it.group == VirtualizationSignalGroup.HOST_APPS }

    val dangerSignals: List<VirtualizationSignal>
        get() = signals.filter {
            it.severity == VirtualizationSignalSeverity.DANGER &&
                    it.group != VirtualizationSignalGroup.HOST_APPS
        }

    val warningSignals: List<VirtualizationSignal>
        get() = signals.filter { it.severity == VirtualizationSignalSeverity.WARNING }

    val onlyHostAppCorroboration: Boolean
        get() = hostAppCorroborationCount > 0 &&
                dangerSignals.isEmpty() &&
                warningSignals.isEmpty()

    companion object {
        fun loading(): VirtualizationReport {
            return VirtualizationReport(
                stage = VirtualizationStage.LOADING,
                nativeAvailable = true,
                startupPreloadAvailable = false,
                startupPreloadContextValid = false,
                crossProcessAvailable = false,
                isolatedProcessAvailable = false,
                asmSupported = false,
                eglAvailable = false,
                packageVisibility = InstalledPackageVisibility.UNKNOWN,
                dexPathEntryCount = 0,
                dexPathHitCount = 0,
                uidIdentityHitCount = 0,
                environmentHitCount = 0,
                translationHitCount = 0,
                runtimeArtifactHitCount = 0,
                consistencyHitCount = 0,
                isolatedConsistencyHitCount = 0,
                mountAnchorDriftCount = 0,
                mountNamespaceAvailable = false,
                honeypotHitCount = 0,
                syscallPackSupported = false,
                syscallPackHitCount = 0,
                hostAppCorroborationCount = 0,
                mapLineCount = 0,
                fdCount = 0,
                mountInfoCount = 0,
                signals = emptyList(),
                methods = emptyList(),
                impacts = emptyList(),
            )
        }

        fun failed(message: String): VirtualizationReport {
            return loading().copy(
                stage = VirtualizationStage.FAILED,
                nativeAvailable = false,
                errorMessage = message,
            )
        }
    }
}
