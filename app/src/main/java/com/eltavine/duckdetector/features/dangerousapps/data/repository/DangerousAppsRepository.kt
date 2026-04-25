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

package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.content.Context
import android.os.IBinder
import android.os.Parcel
import android.provider.Settings
import android.text.TextUtils
import com.eltavine.duckdetector.features.dangerousapps.data.native.DangerousAppsNativeBridge
import com.eltavine.duckdetector.features.dangerousapps.data.probes.OpenApkFdPackageProbe
import com.eltavine.duckdetector.features.dangerousapps.data.probes.SceneLoopbackProbe
import com.eltavine.duckdetector.features.dangerousapps.data.rules.DangerousAppsCatalog
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppFinding
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppTarget
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsReport
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousAppsStage
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethod
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousDetectionMethodKind
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DangerousAppsRepository(
    private val context: Context,
    private val nativeBridge: DangerousAppsNativeBridge = DangerousAppsNativeBridge(),
    private val openApkFdPackageProbe: OpenApkFdPackageProbe = OpenApkFdPackageProbe(),
    private val sceneLoopbackProbe: SceneLoopbackProbe = SceneLoopbackProbe(),
) {

    suspend fun scan(): DangerousAppsReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                DangerousAppsReport.failed(
                    targets = DangerousAppsCatalog.targets,
                    message = throwable.message ?: "Dangerous app scan failed.",
                )
            }
    }

    private fun scanInternal(): DangerousAppsReport {
        val targets = DangerousAppsCatalog.targets
        val detectedApps = linkedMapOf<String, MutableFinding>()
        val issues = mutableListOf<String>()

        val installedPackages = PackageVisibilityChecker.getInstalledPackages(context)
        val packageManagerVisibleCount = installedPackages.size
        val packageVisibility = PackageVisibilityChecker.detect(context, packageManagerVisibleCount)
        val suspiciousLowPmInventory = PackageVisibilityChecker.hasSuspiciouslyLowInventory(
            packageVisibility = packageVisibility,
            installedPackageCount = packageManagerVisibleCount,
        )

        if (packageVisibility == DangerousPackageVisibility.RESTRICTED) {
            issues += "PackageManager visibility is restricted on this device profile."
        }
        if (suspiciousLowPmInventory) {
            issues += "PackageManager returned only $packageManagerVisibleCount visible packages despite a full inventory result. This can happen under HMA-style whitelist filtering."
        }

        if (packageVisibility == DangerousPackageVisibility.FULL) {
            targets.forEach { target ->
                if (target.packageName in installedPackages) {
                    appendMethod(
                        detectedApps = detectedApps,
                        target = target,
                        method = DangerousDetectionMethod(DangerousDetectionMethodKind.PACKAGE_MANAGER),
                    )
                }
            }
        }

        openApkFdPackageProbe
            .run(targets.mapTo(linkedSetOf()) { it.packageName })
            .detectedPackages
            .forEach { packageName ->
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = packageName,
                    method = DangerousDetectionMethod(DangerousDetectionMethodKind.OPEN_APK_FD),
                )
            }

        enumerateAndroidDirsByListing().forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.DIRECTORY_LISTING),
            )
        }

        enumerateAndroidDirsByZeroWidthBypass().forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.ZWC_BYPASS),
            )
        }

        enumerateAndroidDirsByIgnorableCodePoints().forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.IGNORABLE_CODEPOINT_BYPASS),
            )
        }

        targets.forEach { target ->
            if (checkFuseDataPath(target.packageName)) {
                appendMethod(
                    detectedApps = detectedApps,
                    target = target,
                    method = DangerousDetectionMethod(DangerousDetectionMethodKind.FUSE_STAT),
                )
            }
        }

        nativeBridge.statPackages(targets.map { it.packageName }).forEach { packageName ->
            appendMethod(
                detectedApps = detectedApps,
                packageName = packageName,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.NATIVE_DATA_STAT),
            )
        }

        DangerousAppsCatalog.specialPathDetection.forEach { (path, packageName) ->
            if (checkPathExists(path)) {
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = packageName,
                    method = DangerousDetectionMethod(
                        kind = DangerousDetectionMethodKind.SPECIAL_PATH,
                        detail = path,
                        hmaEligible = path !in DangerousAppsCatalog.excludedPathsForHmaInference,
                    ),
                )
            }
        }

        if (detectThanoxIpc()) {
            appendMethod(
                detectedApps = detectedApps,
                packageName = THANOX_PACKAGE,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.THANOX_IPC),
            )
        }

        if (isAccessibilityServiceEnabled(SCENE_PACKAGE)) {
            appendMethod(
                detectedApps = detectedApps,
                packageName = SCENE_PACKAGE,
                method = DangerousDetectionMethod(DangerousDetectionMethodKind.ACCESSIBILITY_SERVICE),
            )
        }

        sceneLoopbackProbe.probe()
            .takeIf { it.detected }
            ?.let { result ->
                appendMethod(
                    detectedApps = detectedApps,
                    packageName = SCENE_PACKAGE,
                    method = DangerousDetectionMethod(
                        kind = DangerousDetectionMethodKind.SCENE_LOOPBACK,
                        detail = result.detail,
                    ),
                )
            }

        val findings = buildFindings(detectedApps)
        val hiddenFromPackageManager = if (packageVisibility == DangerousPackageVisibility.FULL) {
            findings.filter { finding ->
                finding.target.packageName !in installedPackages &&
                        finding.methods.any { it.kind != DangerousDetectionMethodKind.PACKAGE_MANAGER && it.hmaEligible }
            }
        } else {
            emptyList()
        }

        return DangerousAppsReport(
            stage = DangerousAppsStage.READY,
            packageVisibility = packageVisibility,
            packageManagerVisibleCount = packageManagerVisibleCount,
            suspiciousLowPmInventory = suspiciousLowPmInventory,
            targets = targets,
            findings = findings,
            hiddenFromPackageManager = hiddenFromPackageManager,
            probesRan = buildProbeList(packageVisibility),
            issues = issues,
        )
    }

    private fun buildFindings(
        detectedApps: Map<String, MutableFinding>,
    ): List<DangerousAppFinding> {
        return DangerousAppsCatalog.targets.mapNotNull { target ->
            detectedApps[target.packageName]?.let { finding ->
                DangerousAppFinding(
                    target = target,
                    methods = finding.methods.sortedWith(
                        compareBy<DangerousDetectionMethod>(
                            { it.kind.ordinal },
                            { it.displayText }),
                    ),
                )
            }
        }
    }

    private fun buildProbeList(
        packageVisibility: DangerousPackageVisibility,
    ): List<DangerousDetectionMethodKind> {
        return buildList {
            if (packageVisibility == DangerousPackageVisibility.FULL) {
                add(DangerousDetectionMethodKind.PACKAGE_MANAGER)
            }
            add(DangerousDetectionMethodKind.OPEN_APK_FD)
            add(DangerousDetectionMethodKind.DIRECTORY_LISTING)
            add(DangerousDetectionMethodKind.ZWC_BYPASS)
            add(DangerousDetectionMethodKind.IGNORABLE_CODEPOINT_BYPASS)
            add(DangerousDetectionMethodKind.FUSE_STAT)
            add(DangerousDetectionMethodKind.NATIVE_DATA_STAT)
            add(DangerousDetectionMethodKind.SPECIAL_PATH)
            add(DangerousDetectionMethodKind.SCENE_LOOPBACK)
            add(DangerousDetectionMethodKind.THANOX_IPC)
            add(DangerousDetectionMethodKind.ACCESSIBILITY_SERVICE)
        }
    }

    private fun appendMethod(
        detectedApps: MutableMap<String, MutableFinding>,
        target: DangerousAppTarget,
        method: DangerousDetectionMethod,
    ) {
        detectedApps
            .getOrPut(target.packageName) { MutableFinding(target) }
            .methods
            .add(method)
    }

    private fun appendMethod(
        detectedApps: MutableMap<String, MutableFinding>,
        packageName: String,
        method: DangerousDetectionMethod,
    ) {
        val target = DangerousAppsCatalog.targetByPackage[packageName] ?: return
        appendMethod(detectedApps, target, method)
    }

    private fun enumerateAndroidDirsByListing(): Set<String> {
        val dirs = linkedSetOf<String>()
        listOf("/sdcard/Android/data", "/sdcard/Android/obb").forEach { targetPath ->
            runCatching {
                File(targetPath)
                    .listFiles()
                    ?.filter { it.isDirectory }
                    ?.mapTo(dirs) { it.name }
            }
            dirs += execDirectoryListing("ls", targetPath)
        }
        return dirs
    }

    private fun enumerateAndroidDirsByZeroWidthBypass(): Set<String> {
        val basePath = "/sdcard/Android/data/"
        val bypassPath = basePath.dropLast(1) + ZERO_WIDTH_SPACE + basePath.last()
        return execDirectoryListing("ls", bypassPath)
    }

    private fun enumerateAndroidDirsByIgnorableCodePoints(): Set<String> {
        val dirs = linkedSetOf<String>()
        val targetDirs = listOf("/sdcard/Android/data", "/sdcard/Android/obb")

        targetDirs.forEach { targetPath ->
            for (bypassChar in IGNORABLE_CODE_POINTS) {
                if (dirs.size > 50) {
                    break
                }
                val bypassPaths = listOf(
                    "$targetPath$bypassChar/",
                    "/sdcard/${bypassChar}Android/${targetPath.substringAfterLast("/")}",
                    "/sdcard$bypassChar/Android/${targetPath.substringAfterLast("/")}",
                )
                bypassPaths.forEach { bypassPath ->
                    dirs += execDirectoryListing("ls", bypassPath, timeoutSeconds = 1L)
                    if (dirs.isNotEmpty()) {
                        return@forEach
                    }
                }
                if (dirs.isNotEmpty()) {
                    break
                }
            }
        }

        return dirs
    }

    private fun execDirectoryListing(
        vararg command: String,
        timeoutSeconds: Long = PROCESS_TIMEOUT_SECONDS,
    ): Set<String> {
        var process: Process? = null
        return try {
            process = ProcessBuilder(command.toList())
                .redirectErrorStream(true)
                .start()
            val result = linkedSetOf<String>()
            process.inputStream.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val dirName = line.trim()
                    if (dirName.isNotEmpty() && dirName != "." && dirName != "..") {
                        result += dirName
                    }
                }
            }
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return emptySet()
            }
            result
        } catch (_: Exception) {
            emptySet()
        } finally {
            process?.destroy()
        }
    }

    private fun checkFuseDataPath(packageName: String): Boolean {
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

    private fun checkPathExists(path: String): Boolean {
        if (runCatching { File(path).exists() }.getOrDefault(false)) {
            return true
        }
        var process: Process? = null
        return try {
            process = ProcessBuilder(listOf("test", "-e", path))
                .redirectErrorStream(true)
                .start()
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                false
            } else {
                process.exitValue() == 0
            }
        } catch (_: Exception) {
            false
        } finally {
            process?.destroy()
        }
    }

    @Suppress("PrivateApi")
    private fun detectThanoxIpc(): Boolean {
        var data: Parcel? = null
        var reply: Parcel? = null
        return try {
            val serviceManagerClass = Class.forName("android.os.ServiceManager")
            val getServiceMethod = serviceManagerClass.getMethod("getService", String::class.java)
            val dropboxBinder = getServiceMethod.invoke(null, THANOX_PROXIED_SERVICE) as? IBinder
                ?: return false

            data = Parcel.obtain()
            reply = Parcel.obtain()

            val result = dropboxBinder.transact(THANOX_IPC_TRANS_CODE, data, reply, 0)
            if (!result) {
                return false
            }
            reply.setDataPosition(0)
            reply.dataSize() > 0
        } catch (_: Exception) {
            false
        } finally {
            data?.recycle()
            reply?.recycle()
        }
    }

    private fun isAccessibilityServiceEnabled(packageName: String): Boolean {
        return try {
            val enabledServices = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
            ) ?: return false

            val services = TextUtils.SimpleStringSplitter(':').apply {
                setString(enabledServices)
            }

            services.any { service -> service.startsWith("$packageName/") }
        } catch (_: Exception) {
            false
        }
    }

    private data class MutableFinding(
        val target: DangerousAppTarget,
        val methods: LinkedHashSet<DangerousDetectionMethod> = linkedSetOf(),
    )

    companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 5L
        private const val ZERO_WIDTH_SPACE = "\u200B"
        private const val THANOX_PROXIED_SERVICE = "dropbox"
        private const val THANOX_PACKAGE = "github.tornaco.android.thanos"
        private const val SCENE_PACKAGE = "com.omarea.vtools"
        private val THANOX_IPC_TRANS_CODE =
            "github.tornaco.android.thanos.core.IPC_TRANS_CODE_THANOS_SERVER".hashCode()

        private val IGNORABLE_CODE_POINTS = listOf(
            "\u00AD",
            "\uFE02",
            "\uFE0F",
            "\uFEFF",
            "\uFFA0",
        )
    }
}
