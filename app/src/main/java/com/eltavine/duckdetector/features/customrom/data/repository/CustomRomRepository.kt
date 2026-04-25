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

package com.eltavine.duckdetector.features.customrom.data.repository

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import com.eltavine.duckdetector.features.customrom.data.native.CustomRomNativeBridge
import com.eltavine.duckdetector.features.customrom.data.rules.CustomRomCatalog
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodOutcome
import com.eltavine.duckdetector.features.customrom.domain.CustomRomMethodResult
import com.eltavine.duckdetector.features.customrom.domain.CustomRomPackageVisibility
import com.eltavine.duckdetector.features.customrom.domain.CustomRomReport
import com.eltavine.duckdetector.features.customrom.domain.CustomRomStage
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class CustomRomRepository(
    private val context: Context,
    private val nativeBridge: CustomRomNativeBridge = CustomRomNativeBridge(),
    private val fileExists: (String) -> Boolean = { path -> File(path).exists() },
) {

    suspend fun scan(): CustomRomReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                CustomRomReport.failed(throwable.message ?: "Custom ROM scan failed.")
            }
    }

    private fun scanInternal(): CustomRomReport {
        val isPixel = isPixelDevice()
        val propertyFindings = detectPropertyFindings(isPixel)
        val buildFindings = detectBuildFindings(isPixel)
        val installedPackages = getInstalledPackages()
        val packageVisibility = detectPackageVisibility(installedPackages.size)
        val packageFindings = detectPackageFindings(installedPackages, isPixel)
        val (serviceFindings, listedServiceCount) = detectServiceFindings(isPixel)
        val reflectionFindings = detectReflectionFindings(isPixel)
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val platformFileFindings =
            CustomRomPlatformFileResolver.resolve(
                nativeSnapshot = nativeSnapshot,
                isPixel = isPixel,
                shouldSkip = ::shouldSkip,
                fileExists = fileExists,
            )
        val resourceInjectionFindings = nativeSnapshot.resourceInjectionFindings
        val policyFindings =
            nativeSnapshot.policyFindings.filterNot { shouldSkip(it.romName, isPixel) }
        val overlayFindings =
            nativeSnapshot.overlayFindings.filterNot { shouldSkip(it.romName, isPixel) }

        val detectedRoms = linkedSetOf<String>().apply {
            addAll(propertyFindings.map { it.romName })
            addAll(buildFindings.map { it.romName })
            addAll(packageFindings.map { it.romName })
            addAll(serviceFindings.map { it.romName })
            addAll(reflectionFindings.map { it.romName })
            addAll(platformFileFindings.map { it.romName })
            addAll(resourceInjectionFindings.map { it.romName })
            addAll(policyFindings.map { it.romName })
            addAll(overlayFindings.map { it.romName })
            if (nativeSnapshot.recoveryScripts.isNotEmpty()) {
                add("Custom ROM")
            }
        }.toList()

        val methods = buildMethods(
            propertyFindings = propertyFindings,
            buildFindings = buildFindings,
            packageFindings = packageFindings,
            packageVisibility = packageVisibility,
            serviceFindings = serviceFindings,
            listedServiceCount = listedServiceCount,
            reflectionFindings = reflectionFindings,
            platformFileFindings = platformFileFindings,
            resourceInjectionFindings = resourceInjectionFindings,
            recoveryScripts = nativeSnapshot.recoveryScripts,
            policyFindings = policyFindings,
            overlayFindings = overlayFindings,
            nativeAvailable = nativeSnapshot.available,
        )

        return CustomRomReport(
            stage = CustomRomStage.READY,
            packageVisibility = packageVisibility,
            detectedRoms = detectedRoms,
            propertyFindings = propertyFindings,
            buildFindings = buildFindings,
            packageFindings = packageFindings,
            serviceFindings = serviceFindings,
            reflectionFindings = reflectionFindings,
            platformFileFindings = platformFileFindings,
            resourceInjectionFindings = resourceInjectionFindings,
            recoveryScripts = nativeSnapshot.recoveryScripts,
            policyFindings = policyFindings,
            overlayFindings = overlayFindings,
            nativeAvailable = nativeSnapshot.available,
            checkedPropertyCount = CustomRomCatalog.propertySignatures.size,
            checkedBuildFieldCount = CustomRomCatalog.buildFields.size,
            checkedPackageCount = CustomRomCatalog.packageSignatures.size,
            checkedServiceCount = CustomRomCatalog.specificServices.size,
            listedServiceCount = listedServiceCount,
            methods = methods,
        )
    }

    private fun detectPropertyFindings(
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        return CustomRomCatalog.propertySignatures.mapNotNull { signature ->
            val value = readSystemProperty(signature.property)?.takeIf { it.isNotBlank() }
                ?: return@mapNotNull null
            if (shouldSkip(signature.romName, isPixel)) {
                return@mapNotNull null
            }
            CustomRomFinding(
                romName = signature.romName,
                signal = signature.property,
                detail = value,
            )
        }.distinct()
    }

    private fun detectBuildFindings(
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        val fieldValues = listOf(
            "Build.DISPLAY" to Build.DISPLAY,
            "Build.FINGERPRINT" to Build.FINGERPRINT,
            "Build.HOST" to Build.HOST,
        )

        return buildList {
            fieldValues.forEach { (fieldName, rawValue) ->
                val value = rawValue?.takeIf { it.isNotBlank() } ?: return@forEach
                val lower = value.lowercase()
                CustomRomCatalog.buildFieldKeywords.forEach { signature ->
                    if (lower.contains(signature.keyword) && !shouldSkip(
                            signature.romName,
                            isPixel
                        )
                    ) {
                        add(
                            CustomRomFinding(
                                romName = signature.romName,
                                signal = fieldName,
                                detail = value,
                            ),
                        )
                    }
                }
            }
        }.distinct()
    }

    private fun detectPackageFindings(
        installedPackages: Set<String>,
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        return CustomRomCatalog.packageSignatures.mapNotNull { signature ->
            if (signature.packageName !in installedPackages || shouldSkip(
                    signature.romName,
                    isPixel
                )
            ) {
                return@mapNotNull null
            }
            CustomRomFinding(
                romName = signature.romName,
                signal = signature.appName,
                detail = signature.packageName,
            )
        }.distinct()
    }

    @Suppress("PrivateApi")
    private fun detectServiceFindings(
        isPixel: Boolean,
    ): Pair<List<CustomRomFinding>, Int> {
        val findings = linkedSetOf<CustomRomFinding>()
        var listedServiceCount = 0

        runCatching {
            val serviceManagerClass = Class.forName("android.os.ServiceManager")
            val getServiceMethod = serviceManagerClass.getMethod("getService", String::class.java)

            CustomRomCatalog.specificServices.forEach { signature ->
                val binder = getServiceMethod.invoke(null, signature.serviceName) as? IBinder
                if (binder != null && !shouldSkip(signature.romName, isPixel)) {
                    findings += CustomRomFinding(
                        romName = signature.romName,
                        signal = signature.serviceName,
                        detail = "ServiceManager.getService",
                    )
                }
            }

            runCatching {
                val listServicesMethod = serviceManagerClass.getMethod("listServices")
                val services = listServicesMethod.invoke(null) as? Array<*>
                val serviceNames = services?.filterIsInstance<String>().orEmpty()
                listedServiceCount = serviceNames.size
                serviceNames.forEach { serviceName ->
                    val lower = serviceName.lowercase()
                    CustomRomCatalog.servicePatterns.forEach { (pattern, romName) ->
                        if (lower.contains(pattern) && !shouldSkip(romName, isPixel)) {
                            findings += CustomRomFinding(
                                romName = romName,
                                signal = serviceName,
                                detail = "ServiceManager.listServices",
                            )
                        }
                    }
                }
            }
        }

        return findings.toList() to listedServiceCount
    }

    private fun detectReflectionFindings(
        isPixel: Boolean,
    ): List<CustomRomFinding> {
        return buildList {
            CustomRomCatalog.reflectionTargets.forEach { target ->
                if (shouldSkip(target.romName, isPixel)) {
                    return@forEach
                }
                runCatching {
                    val clazz = Class.forName(target.className)
                    val field = clazz.getDeclaredField(target.fieldName)
                    field.isAccessible = true
                    val value = field.get(null)?.toString()?.takeIf { it.isNotBlank() }
                        ?: return@runCatching
                    add(
                        CustomRomFinding(
                            romName = target.romName,
                            signal = "${target.className}.${target.fieldName}",
                            detail = value,
                        ),
                    )
                }
            }
        }.distinct()
    }

    private fun buildMethods(
        propertyFindings: List<CustomRomFinding>,
        buildFindings: List<CustomRomFinding>,
        packageFindings: List<CustomRomFinding>,
        packageVisibility: CustomRomPackageVisibility,
        serviceFindings: List<CustomRomFinding>,
        listedServiceCount: Int,
        reflectionFindings: List<CustomRomFinding>,
        platformFileFindings: List<CustomRomFinding>,
        resourceInjectionFindings: List<CustomRomFinding>,
        recoveryScripts: List<String>,
        policyFindings: List<CustomRomFinding>,
        overlayFindings: List<CustomRomFinding>,
        nativeAvailable: Boolean,
    ): List<CustomRomMethodResult> {
        val nativeFileCount =
            platformFileFindings.size + recoveryScripts.size + overlayFindings.size
        return listOf(
            CustomRomMethodResult(
                label = "propertyScan",
                summary = if (propertyFindings.isNotEmpty()) "${propertyFindings.size} hit(s)" else "Clean",
                outcome = if (propertyFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
                detail = propertyFindings.takeIf { it.isNotEmpty() }
                    ?.joinToString(separator = "\n") {
                        "${it.signal} = ${it.detail}"
                    },
            ),
            CustomRomMethodResult(
                label = "buildFieldScan",
                summary = if (buildFindings.isNotEmpty()) "${buildFindings.size} hit(s)" else "Clean",
                outcome = if (buildFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
                detail = buildFindings.takeIf { it.isNotEmpty() }?.joinToString(separator = "\n") {
                    "${it.signal} = ${it.detail}"
                },
            ),
            CustomRomMethodResult(
                label = "packageScan",
                summary = when {
                    packageFindings.isNotEmpty() -> "${packageFindings.size} package(s)"
                    packageVisibility == CustomRomPackageVisibility.RESTRICTED -> "Scoped"
                    else -> "Clean"
                },
                outcome = when {
                    packageFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                    packageVisibility == CustomRomPackageVisibility.RESTRICTED -> CustomRomMethodOutcome.SUPPORT
                    else -> CustomRomMethodOutcome.CLEAN
                },
                detail = when {
                    packageFindings.isNotEmpty() -> packageFindings.joinToString(separator = "\n") {
                        "${it.signal}: ${it.detail}"
                    }

                    packageVisibility == CustomRomPackageVisibility.RESTRICTED ->
                        "PackageManager visibility looked restricted on this device profile."

                    else -> null
                },
            ),
            CustomRomMethodResult(
                label = "serviceScan",
                summary = if (serviceFindings.isNotEmpty()) "${serviceFindings.size} service(s)" else "Clean",
                outcome = if (serviceFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
                detail = buildString {
                    append("Listed services: $listedServiceCount")
                    if (serviceFindings.isNotEmpty()) {
                        appendLine()
                        append(
                            serviceFindings.joinToString(separator = "\n") {
                                "${it.signal}: ${it.detail}"
                            },
                        )
                    }
                },
            ),
            CustomRomMethodResult(
                label = "reflectionScan",
                summary = if (reflectionFindings.isNotEmpty()) "Constants found" else "Clean",
                outcome = if (reflectionFindings.isNotEmpty()) CustomRomMethodOutcome.DETECTED else CustomRomMethodOutcome.CLEAN,
                detail = reflectionFindings.takeIf { it.isNotEmpty() }
                    ?.joinToString(separator = "\n") {
                        "${it.signal} = ${it.detail}"
                    },
            ),
            CustomRomMethodResult(
                label = "mapsInjection",
                summary = when {
                    resourceInjectionFindings.isNotEmpty() -> "${resourceInjectionFindings.size} trace(s)"
                    nativeAvailable -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    resourceInjectionFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                    nativeAvailable -> CustomRomMethodOutcome.CLEAN
                    else -> CustomRomMethodOutcome.SUPPORT
                },
                detail = resourceInjectionFindings.takeIf { it.isNotEmpty() }
                    ?.joinToString(separator = "\n\n") {
                        "${it.signal}: ${it.detail}"
                    },
            ),
            CustomRomMethodResult(
                label = "nativeFiles",
                summary = when {
                    nativeFileCount > 0 -> "$nativeFileCount trace(s)"
                    nativeAvailable -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    nativeFileCount > 0 -> CustomRomMethodOutcome.DETECTED
                    nativeAvailable -> CustomRomMethodOutcome.CLEAN
                    else -> CustomRomMethodOutcome.SUPPORT
                },
                detail = buildNativeFilesDetail(
                    platformFileFindings,
                    recoveryScripts,
                    overlayFindings
                ),
            ),
            CustomRomMethodResult(
                label = "nativePolicy",
                summary = when {
                    policyFindings.isNotEmpty() -> "${policyFindings.size} hit(s)"
                    nativeAvailable -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    policyFindings.isNotEmpty() -> CustomRomMethodOutcome.DETECTED
                    nativeAvailable -> CustomRomMethodOutcome.CLEAN
                    else -> CustomRomMethodOutcome.SUPPORT
                },
                detail = policyFindings.takeIf { it.isNotEmpty() }?.joinToString(separator = "\n") {
                    "${it.romName}: ${it.detail}"
                },
            ),
            CustomRomMethodResult(
                label = "nativeLibrary",
                summary = if (nativeAvailable) "Loaded" else "Unavailable",
                outcome = if (nativeAvailable) CustomRomMethodOutcome.CLEAN else CustomRomMethodOutcome.SUPPORT,
            ),
        )
    }

    private fun buildNativeFilesDetail(
        platformFileFindings: List<CustomRomFinding>,
        recoveryScripts: List<String>,
        overlayFindings: List<CustomRomFinding>,
    ): String? {
        return buildString {
            platformFileFindings.forEach { finding ->
                appendLine("${finding.romName}: ${finding.detail}")
            }
            recoveryScripts.forEach { script ->
                appendLine("Script: $script")
            }
            overlayFindings.forEach { finding ->
                appendLine("${finding.romName}: ${finding.detail}")
            }
        }.trim().ifBlank { null }
    }

    private fun shouldSkip(
        romName: String,
        isPixel: Boolean,
    ): Boolean {
        return isPixel && romName == "PixelExperience"
    }

    private fun isPixelDevice(): Boolean {
        return Build.BRAND.equals("google", ignoreCase = true) &&
                Build.MODEL.startsWith("Pixel", ignoreCase = true)
    }

    @Suppress("DEPRECATION")
    private fun getInstalledPackages(): Set<String> {
        return runCatching {
            val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
                )
            } else {
                context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            }
            applications.mapTo(linkedSetOf()) { it.packageName }
        }.getOrDefault(emptySet())
    }

    private fun detectPackageVisibility(
        installedPackageCount: Int,
    ): CustomRomPackageVisibility {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return CustomRomPackageVisibility.FULL
        }
        return if (installedPackageCount > 10) {
            CustomRomPackageVisibility.FULL
        } else {
            CustomRomPackageVisibility.RESTRICTED
        }
    }

    private fun readSystemProperty(
        name: String,
    ): String? {
        readSystemPropertyViaReflection(name)?.let { value ->
            return value
        }
        return readSystemPropertyViaGetprop(name)
    }

    private fun readSystemPropertyViaReflection(
        name: String,
    ): String? {
        return runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, name) as? String)?.trim()
        }.getOrNull()
    }

    private fun readSystemPropertyViaGetprop(
        name: String,
    ): String? {
        var process: Process? = null
        return try {
            process = ProcessBuilder("getprop", name)
                .redirectErrorStream(true)
                .start()
            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            if (!process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                null
            } else {
                output.takeIf { it.isNotBlank() }
            }
        } catch (_: Exception) {
            null
        } finally {
            process?.destroy()
        }
    }

    companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 3L
    }
}
