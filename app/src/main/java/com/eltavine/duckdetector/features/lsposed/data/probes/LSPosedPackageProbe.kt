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

package com.eltavine.duckdetector.features.lsposed.data.probes

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedPackageVisibility
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class LSPosedPackageProbeResult(
    val signals: List<LSPosedSignal>,
    val managerPackageCount: Int,
    val moduleAppCount: Int,
    val packageVisibility: LSPosedPackageVisibility,
)

class LSPosedPackageProbe {

    @Suppress("DEPRECATION")
    fun run(context: Context): LSPosedPackageProbeResult {
        val packageManager = context.packageManager
        val installedApps = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
                )
            } else {
                packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            }
        }.getOrDefault(emptyList())

        val packageVisibility = when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.R -> LSPosedPackageVisibility.FULL
            installedApps.isEmpty() -> LSPosedPackageVisibility.UNKNOWN
            installedApps.size > 10 -> LSPosedPackageVisibility.FULL
            else -> LSPosedPackageVisibility.RESTRICTED
        }

        val signals = mutableListOf<LSPosedSignal>()
        val installedByPackage = installedApps.associateBy { it.packageName }
        KNOWN_PACKAGES.forEach { (packageName, label) ->
            if (packageName !in installedByPackage) {
                return@forEach
            }
            signals += LSPosedSignal(
                id = "pkg_${packageName.replace('.', '_')}",
                label = label,
                value = "Installed",
                group = LSPosedSignalGroup.PACKAGES,
                severity = LSPosedSignalSeverity.WARNING,
                detail = packageName,
                detailMonospace = true,
            )
        }

        val moduleSignals = installedApps.mapNotNull { appInfo ->
            val metaData = appInfo.metaData ?: return@mapNotNull null
            val keys = XPOSED_METADATA_KEYS.filter { metaData.containsKey(it) }
            if (keys.isEmpty()) {
                return@mapNotNull null
            }
            LSPosedSignal(
                id = "module_${appInfo.packageName.replace('.', '_')}",
                label = appLabel(packageManager, appInfo),
                value = "Module",
                group = LSPosedSignalGroup.PACKAGES,
                severity = LSPosedSignalSeverity.WARNING,
                detail = buildString {
                    appendLine(appInfo.packageName)
                    append("Meta-data: ")
                    append(keys.joinToString())
                },
                detailMonospace = true,
            )
        }
        signals += moduleSignals

        return LSPosedPackageProbeResult(
            signals = signals,
            managerPackageCount = KNOWN_PACKAGES.count { (packageName, _) -> packageName in installedByPackage },
            moduleAppCount = moduleSignals.size,
            packageVisibility = packageVisibility,
        )
    }

    private fun appLabel(
        packageManager: PackageManager,
        appInfo: ApplicationInfo,
    ): String {
        return runCatching {
            packageManager.getApplicationLabel(appInfo).toString()
        }.getOrDefault(appInfo.packageName)
    }

    private companion object {
        private val KNOWN_PACKAGES = linkedMapOf(
            "org.lsposed.manager" to "LSPosed Manager",
            "org.lsposed.manager.debug" to "LSPosed Debug",
            "moe.matsuri.lsposed" to "LSPosed Fork",
            "org.lsposed.lspatch" to "LSPatch",
            "de.robv.android.xposed.installer" to "Xposed Installer",
            "org.meowcat.edxposed.manager" to "EdXposed Manager",
            "com.solohsu.android.edxp.manager" to "EdXposed Manager (old)",
            "me.weishu.exp" to "TaiChi/Exposed",
            "io.va.exposed" to "VirtualXposed",
            "com.tsng.hidemyapplist" to "Hide My Applist",
            "eu.faircode.xlua" to "XLua",
        )

        private val XPOSED_METADATA_KEYS = listOf(
            "xposedmodule",
            "xposedminversion",
            "xposeddescription",
            "xposedscope",
            "xposedsharedprefs",
        )
    }
}
