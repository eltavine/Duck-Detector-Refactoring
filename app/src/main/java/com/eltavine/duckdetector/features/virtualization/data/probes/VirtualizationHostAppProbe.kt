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

package com.eltavine.duckdetector.features.virtualization.data.probes

import android.content.Context
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.features.dangerousapps.data.native.DangerousAppsNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppTarget
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppsCatalog
import java.io.File

enum class VirtualizationHostDetectionMethodKind(
    val label: String,
) {
    PACKAGE_MANAGER("PackageManager"),
    FUSE_STAT("FUSE stat"),
    NATIVE_DATA_STAT("Native /data/data stat"),
    SPECIAL_PATH("Special path"),
}

data class VirtualizationHostDetectionMethod(
    val kind: VirtualizationHostDetectionMethodKind,
    val detail: String? = null,
)

data class VirtualizationHostAppFinding(
    val target: VirtualizationHostAppTarget,
    val methods: List<VirtualizationHostDetectionMethod>,
)

data class VirtualizationHostAppProbeResult(
    val packageVisibility: InstalledPackageVisibility,
    val findings: List<VirtualizationHostAppFinding>,
    val issues: List<String> = emptyList(),
)

open class VirtualizationHostAppProbe(
    private val context: Context? = null,
    private val nativeBridge: DangerousAppsNativeBridge = DangerousAppsNativeBridge(),
) {

    open fun probe(): VirtualizationHostAppProbeResult {
        val appContext = context?.applicationContext ?: return VirtualizationHostAppProbeResult(
            packageVisibility = InstalledPackageVisibility.UNKNOWN,
            findings = emptyList(),
            issues = listOf("Context unavailable."),
        )

        val detected = linkedMapOf<String, MutableSet<VirtualizationHostDetectionMethod>>()
        val installedPackages = InstalledPackageVisibilityChecker.getInstalledPackages(appContext)
        val packageVisibility = InstalledPackageVisibilityChecker.detect(
            appContext,
            installedPackages.size,
        )

        if (packageVisibility == InstalledPackageVisibility.FULL) {
            VirtualizationHostAppsCatalog.targets.forEach { target ->
                if (target.packageName in installedPackages) {
                    detected
                        .getOrPut(target.packageName) { linkedSetOf() }
                        .add(VirtualizationHostDetectionMethod(VirtualizationHostDetectionMethodKind.PACKAGE_MANAGER))
                }
            }
        }

        VirtualizationHostAppsCatalog.targets.forEach { target ->
            if (checkFusePath(target.packageName)) {
                detected
                    .getOrPut(target.packageName) { linkedSetOf() }
                    .add(VirtualizationHostDetectionMethod(VirtualizationHostDetectionMethodKind.FUSE_STAT))
            }
        }

        nativeBridge.statPackages(VirtualizationHostAppsCatalog.targets.map { it.packageName })
            .forEach { packageName ->
                detected
                    .getOrPut(packageName) { linkedSetOf() }
                    .add(VirtualizationHostDetectionMethod(VirtualizationHostDetectionMethodKind.NATIVE_DATA_STAT))
            }

        VirtualizationHostAppsCatalog.specialPaths.forEach { (path, packageName) ->
            if (runCatching { File(path).exists() }.getOrDefault(false)) {
                detected
                    .getOrPut(packageName) { linkedSetOf() }
                    .add(
                        VirtualizationHostDetectionMethod(
                            kind = VirtualizationHostDetectionMethodKind.SPECIAL_PATH,
                            detail = path,
                        ),
                    )
            }
        }

        val findings = VirtualizationHostAppsCatalog.targets.mapNotNull { target ->
            detected[target.packageName]?.let { methods ->
                VirtualizationHostAppFinding(
                    target = target,
                    methods = methods.sortedBy { it.kind.ordinal },
                )
            }
        }

        val issues = buildList {
            if (packageVisibility == InstalledPackageVisibility.RESTRICTED) {
                add("PackageManager visibility is restricted on this device profile.")
            }
        }

        return VirtualizationHostAppProbeResult(
            packageVisibility = packageVisibility,
            findings = findings,
            issues = issues,
        )
    }

    private fun checkFusePath(packageName: String): Boolean {
        val paths = listOf(
            "/storage/emulated/0/Android/data/$packageName",
            "/storage/emulated/0/Android/obb/$packageName",
        )
        return paths.any { path ->
            runCatching {
                File(path).exists() && File(path).isDirectory
            }.getOrDefault(false)
        }
    }
}
