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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import org.xmlpull.v1.XmlPullParser

private val KERNELSU_MANAGER_PACKAGES = listOf(
    "me.weishu.kernelsu",
    "io.github.a13e300.mksu",
    "com.resukisu.resukisu",
    "com.sukisu.ultra",
    "com.rifsxd.ksunext",
)
private const val EXPECTED_ZYGOTE_PRELOAD_NAME =
    "me.weishu.kernelsu.magica.AppZygotePreload"
private const val ANDROID_NAMESPACE_URI = "http://schemas.android.com/apk/res/android"

data class KernelSuManagerFingerprintProbeResult(
    val available: Boolean,
    val packageVisibility: InstalledPackageVisibility,
    val packagePresent: Boolean,
    val traitHitCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val visibilityRestricted: Boolean
        get() = packageVisibility == InstalledPackageVisibility.RESTRICTED
}

internal data class KernelSuManagerManifestSnapshot(
    val packageName: String = KERNELSU_MANAGER_PACKAGES.first(),
    val versionName: String = "",
    val zygotePreloadName: String = "",
    val isolatedProcessServices: List<String> = emptyList(),
    val appZygoteServices: List<String> = emptyList(),
)

class KernelSuManagerFingerprintProbe(
    private val context: Context? = null,
) {

    fun run(): KernelSuManagerFingerprintProbeResult {
        val appContext =
            context?.applicationContext ?: return KernelSuManagerFingerprintProbeResult(
                available = false,
                packageVisibility = InstalledPackageVisibility.UNKNOWN,
                packagePresent = false,
                traitHitCount = 0,
                findings = emptyList(),
                detail = "Context unavailable.",
            )

        val visiblePackages = InstalledPackageVisibilityChecker.getInstalledPackages(appContext)
        val visibility = InstalledPackageVisibilityChecker.detect(
            context = appContext,
            installedPackageCount = visiblePackages.size,
        )
        val snapshot = loadPackageSnapshot(appContext.packageManager)
            ?: return KernelSuManagerFingerprintProbeResult(
                available = true,
                packageVisibility = visibility,
                packagePresent = false,
                traitHitCount = 0,
                findings = emptyList(),
                detail = if (visibility == InstalledPackageVisibility.RESTRICTED) {
                    "PackageManager visibility is restricted, so known KernelSU manager packages may be hidden."
                } else {
                    "Known KernelSU manager packages were not visible."
                },
            )

        return evaluate(
            packageVisibility = visibility,
            snapshot = snapshot,
        )
    }

    internal fun evaluate(
        packageVisibility: InstalledPackageVisibility,
        snapshot: KernelSuManagerManifestSnapshot,
    ): KernelSuManagerFingerprintProbeResult {
        val traitHitCount = buildList {
            if (snapshot.zygotePreloadName == EXPECTED_ZYGOTE_PRELOAD_NAME) {
                add("zygotePreloadName")
            }
            if (snapshot.isolatedProcessServices.isNotEmpty()) {
                add("isolatedProcess")
            }
            if (snapshot.appZygoteServices.isNotEmpty()) {
                add("useAppZygote")
            }
        }.size

        val detail = buildString {
            append("package=")
            append(snapshot.packageName)
            if (snapshot.versionName.isNotBlank()) {
                append("\nversionName=")
                append(snapshot.versionName)
            }
            append("\nzygotePreloadName=")
            append(snapshot.zygotePreloadName.ifBlank { "<empty>" })
            append("\nisolatedProcess services=")
            append(
                snapshot.isolatedProcessServices.joinToString(separator = ", ")
                    .ifBlank { "<none>" })
            append("\nuseAppZygote services=")
            append(snapshot.appZygoteServices.joinToString(separator = ", ").ifBlank { "<none>" })
            append("\npackageVisibility=")
            append(packageVisibility.name.lowercase())
            append("\nThis is only a weak corroboration signal. Package visibility, repackaging, or a renamed manager can all hide or alter it.")
        }

        return KernelSuManagerFingerprintProbeResult(
            available = true,
            packageVisibility = packageVisibility,
            packagePresent = true,
            traitHitCount = traitHitCount,
            findings = listOf(
                NativeRootFinding(
                    id = "ksu_manager_manifest",
                    label = "KernelSU manager manifest",
                    value = if (traitHitCount > 0) "$traitHitCount/3 traits" else "Present",
                    detail = detail,
                    group = NativeRootGroup.PACKAGE,
                    severity = NativeRootFindingSeverity.WARNING,
                    detailMonospace = true,
                ),
            ),
            detail = detail,
        )
    }

    @Suppress("DEPRECATION")
    internal fun loadPackageSnapshot(packageManager: PackageManager): KernelSuManagerManifestSnapshot? {
        val packageInfo = KERNELSU_MANAGER_PACKAGES.firstNotNullOfOrNull { packageName ->
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.PackageInfoFlags.of(PackageManager.GET_SERVICES.toLong()),
                    )
                } else {
                    packageManager.getPackageInfo(packageName, PackageManager.GET_SERVICES)
                }
            }.getOrNull()
        } ?: return null

        return packageInfo.toSnapshot(packageManager)
    }

    private fun PackageInfo.toSnapshot(packageManager: PackageManager): KernelSuManagerManifestSnapshot {
        val services = services.orEmpty().toList()
        return KernelSuManagerManifestSnapshot(
            packageName = packageName.orEmpty().ifBlank {
                KERNELSU_MANAGER_PACKAGES.first()
            },
            versionName = versionName.orEmpty(),
            zygotePreloadName = readZygotePreloadName(packageManager, applicationInfo),
            isolatedProcessServices = services
                .filter { it.flags and ServiceInfo.FLAG_ISOLATED_PROCESS != 0 }
                .map { it.name.orEmpty() }
                .filter { it.isNotBlank() }
                .distinct()
                .sorted(),
            appZygoteServices = services
                .filter { it.flags and ServiceInfo.FLAG_USE_APP_ZYGOTE != 0 }
                .map { it.name.orEmpty() }
                .filter { it.isNotBlank() }
                .distinct()
                .sorted(),
        )
    }

    private fun readZygotePreloadName(
        packageManager: PackageManager,
        applicationInfo: ApplicationInfo?,
    ): String {
        val appInfo = applicationInfo ?: return ""
        return runCatching {
            packageManager.getResourcesForApplication(appInfo)
                .assets
                .openXmlResourceParser("AndroidManifest.xml")
                .use { parser ->
                    while (parser.eventType != XmlPullParser.END_DOCUMENT) {
                        if (
                            parser.eventType == XmlPullParser.START_TAG &&
                            parser.name == "application"
                        ) {
                            return@use parser.getAttributeValue(
                                ANDROID_NAMESPACE_URI,
                                "zygotePreloadName",
                            ).orEmpty()
                        }
                        parser.next()
                    }
                    ""
                }
        }.getOrNull().orEmpty()
    }
}
