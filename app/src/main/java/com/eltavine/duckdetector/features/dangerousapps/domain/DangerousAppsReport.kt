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

package com.eltavine.duckdetector.features.dangerousapps.domain

enum class DangerousAppsStage {
    LOADING,
    READY,
    FAILED,
}

enum class DangerousPackageVisibility {
    UNKNOWN,
    FULL,
    RESTRICTED,
}

enum class DangerousDetectionMethodKind(
    val label: String,
) {
    PACKAGE_MANAGER("PackageManager"),
    OPEN_APK_FD("Open APK FD"),
    DIRECTORY_LISTING("Android/data Directory Listing"),
    ZWC_BYPASS("Android/data ZWC Bypass"),
    IGNORABLE_CODEPOINT_BYPASS("Android/data Ignorable CodePoint Bypass"),
    FUSE_STAT("FUSE stat"),
    NATIVE_DATA_STAT("Native /data/data stat"),
    SPECIAL_PATH("Special path"),
    SCENE_LOOPBACK("Scene loopback"),
    THANOX_IPC("IPC Probe (DROPBOX_SERVICE)"),
    ACCESSIBILITY_SERVICE("Accessibility Service"),
}

data class DangerousAppTarget(
    val packageName: String,
    val appName: String,
    val category: DangerousAppCategory,
)

data class DangerousDetectionMethod(
    val kind: DangerousDetectionMethodKind,
    val detail: String? = null,
    val hmaEligible: Boolean = true,
) {
    val displayText: String
        get() = detail ?: kind.label
}

data class DangerousAppFinding(
    val target: DangerousAppTarget,
    val methods: List<DangerousDetectionMethod>,
)

data class DangerousAppsReport(
    val stage: DangerousAppsStage,
    val packageVisibility: DangerousPackageVisibility,
    val packageManagerVisibleCount: Int,
    val suspiciousLowPmInventory: Boolean,
    val targets: List<DangerousAppTarget>,
    val findings: List<DangerousAppFinding>,
    val hiddenFromPackageManager: List<DangerousAppFinding>,
    val probesRan: List<DangerousDetectionMethodKind>,
    val issues: List<String> = emptyList(),
) {
    val detectedCount: Int
        get() = findings.size

    val hiddenCount: Int
        get() = hiddenFromPackageManager.size

    companion object {
        fun loading(targets: List<DangerousAppTarget>): DangerousAppsReport {
            return DangerousAppsReport(
                stage = DangerousAppsStage.LOADING,
                packageVisibility = DangerousPackageVisibility.UNKNOWN,
                packageManagerVisibleCount = 0,
                suspiciousLowPmInventory = false,
                targets = targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
            )
        }

        fun failed(
            targets: List<DangerousAppTarget>,
            message: String,
        ): DangerousAppsReport {
            return DangerousAppsReport(
                stage = DangerousAppsStage.FAILED,
                packageVisibility = DangerousPackageVisibility.UNKNOWN,
                packageManagerVisibleCount = 0,
                suspiciousLowPmInventory = false,
                targets = targets,
                findings = emptyList(),
                hiddenFromPackageManager = emptyList(),
                probesRan = emptyList(),
                issues = listOf(message),
            )
        }
    }
}
