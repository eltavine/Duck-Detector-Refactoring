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

package com.eltavine.duckdetector.features.deviceinfo.data.repository

import android.app.ActivityManager
import android.content.Context
import android.content.pm.ServiceInfo
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.Display
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoEntry
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoReport
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoSection
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

class DeviceInfoRepository(
    context: Context,
) {

    private val appContext = context.applicationContext

    suspend fun scan(): DeviceInfoReport = withContext(Dispatchers.Default) {
        runCatching {
            buildReport()
        }.getOrElse { throwable ->
            DeviceInfoReport.failed(throwable.message ?: "Device info collection failed.")
        }
    }

    private fun buildReport(): DeviceInfoReport {
        val configuration = appContext.resources.configuration
        val displayMetrics = appContext.resources.displayMetrics
        val locale = configuration.locales[0] ?: Locale.getDefault()
        val displayManager = appContext.getSystemService(DisplayManager::class.java)
        val display = displayManager?.getDisplay(Display.DEFAULT_DISPLAY)
            ?: displayManager?.displays?.firstOrNull()
        val resolution = "${displayMetrics.widthPixels} x ${displayMetrics.heightPixels}"
        val density = "${displayMetrics.densityDpi} dpi (${formatDecimal(displayMetrics.density)}x)"
        val refreshRate =
            display?.refreshRate?.takeIf { it > 0f }?.let { "${formatDecimal(it)} Hz" }
                ?: "Unavailable"
        val kernelVersion = System.getProperty("os.version").orUnavailable()

        // Collect SOC / chipset information
        val socManufacturer = readSocManufacturer()
        val socModel = readSocModel()
        val cpuHardware = readCpuHardware()
        val boardPlatform = readSystemProperty("ro.board.platform")
        val chipName = readSystemProperty("ro.chipname")
        val cpuCores = Runtime.getRuntime().availableProcessors().toString()
        val cpuArch = System.getProperty("os.arch").orUnavailable()
        val cpuAbiList = Build.SUPPORTED_ABIS.joinToString()

        val isolatedProcessSupport = checkIsolatedProcessSupport()

        val sections = listOf(
            DeviceInfoSection(
                title = "Identity",
                entries = listOf(
                    DeviceInfoEntry("Brand", Build.BRAND.orUnavailable()),
                    DeviceInfoEntry("Manufacturer", Build.MANUFACTURER.orUnavailable()),
                    DeviceInfoEntry("Model", Build.MODEL.orUnavailable()),
                    DeviceInfoEntry("Device", Build.DEVICE.orUnavailable()),
                    DeviceInfoEntry("Product", Build.PRODUCT.orUnavailable()),
                    DeviceInfoEntry("Board", Build.BOARD.orUnavailable()),
                ),
            ),
            DeviceInfoSection(
                title = "SOC / Chipset",
                entries = listOf(
                    DeviceInfoEntry(
                        "SOC Manufacturer",
                        socManufacturer.orUnavailable(),
                    ),
                    DeviceInfoEntry(
                        "SOC Model",
                        socModel.orUnavailable(),
                    ),
                    DeviceInfoEntry(
                        "CPU Hardware",
                        cpuHardware.orUnavailable(),
                        detailMonospace = true
                    ),
                    DeviceInfoEntry(
                        "Board Platform",
                        boardPlatform.orUnavailable(),
                        detailMonospace = true
                    ),
                    DeviceInfoEntry(
                        "Chip Name",
                        chipName.orUnavailable(),
                        detailMonospace = true
                    ),
                    DeviceInfoEntry(
                        "CPU Cores",
                        cpuCores,
                    ),
                    DeviceInfoEntry(
                        "CPU Architecture",
                        cpuArch,
                    ),
                    DeviceInfoEntry(
                        "ABI List",
                        cpuAbiList.orUnavailable(),
                        detailMonospace = true
                    ),
                ),
            ),
            DeviceInfoSection(
                title = "Build",
                entries = listOf(
                    DeviceInfoEntry("Hardware", Build.HARDWARE.orUnavailable()),
                    DeviceInfoEntry("Bootloader", Build.BOOTLOADER.orUnavailable()),
                    DeviceInfoEntry(
                        "Fingerprint",
                        Build.FINGERPRINT.orUnavailable(),
                        detailMonospace = true
                    ),
                    DeviceInfoEntry("Build ID", Build.ID.orUnavailable()),
                    DeviceInfoEntry("Incremental", Build.VERSION.INCREMENTAL.orUnavailable()),
                    DeviceInfoEntry("Build type", Build.TYPE.orUnavailable()),
                ),
            ),
            DeviceInfoSection(
                title = "Android",
                entries = listOf(
                    DeviceInfoEntry("Tags", Build.TAGS.orUnavailable()),
                    DeviceInfoEntry("Build user", Build.USER.orUnavailable()),
                    DeviceInfoEntry("Build host", Build.HOST.orUnavailable()),
                    DeviceInfoEntry("SDK", Build.VERSION.SDK_INT.toString()),
                    DeviceInfoEntry("Release", Build.VERSION.RELEASE.orUnavailable()),
                    DeviceInfoEntry("Codename", Build.VERSION.CODENAME.orUnavailable()),
                ),
            ),
            DeviceInfoSection(
                title = "Runtime",
                entries = listOf(
                    DeviceInfoEntry("Security patch", Build.VERSION.SECURITY_PATCH.orUnavailable()),
                    DeviceInfoEntry("Preview SDK", Build.VERSION.PREVIEW_SDK_INT.toString()),
                    DeviceInfoEntry(
                        "Primary ABI",
                        Build.SUPPORTED_ABIS.firstOrNull().orUnavailable()
                    ),
                    DeviceInfoEntry(
                        "ABI list",
                        Build.SUPPORTED_ABIS.joinToString().orUnavailable(),
                        detailMonospace = true
                    ),
                    DeviceInfoEntry(
                        "32-bit ABIs",
                        Build.SUPPORTED_32_BIT_ABIS.joinToString().orUnavailable(),
                        detailMonospace = true
                    ),
                    DeviceInfoEntry(
                        "64-bit ABIs",
                        Build.SUPPORTED_64_BIT_ABIS.joinToString().orUnavailable(),
                        detailMonospace = true
                    ),
                ),
            ),
            DeviceInfoSection(
                title = "Context",
                entries = listOf(
                    DeviceInfoEntry("Kernel", kernelVersion, detailMonospace = true),
                    DeviceInfoEntry("Locale", locale.toLanguageTag().orUnavailable()),
                    DeviceInfoEntry("Time zone", TimeZone.getDefault().id.orUnavailable()),
                    DeviceInfoEntry("Resolution", resolution),
                    DeviceInfoEntry("Density", density),
                    DeviceInfoEntry("Refresh rate", refreshRate),
                    DeviceInfoEntry("Isolated process", isolatedProcessSupport),
                ),
            ),
        )

        return DeviceInfoReport(
            stage = DeviceInfoStage.READY,
            sections = sections,
        )
    }

    private fun String?.orUnavailable(): String {
        return this?.trim()?.takeIf { it.isNotEmpty() } ?: "Unavailable"
    }

    private fun formatDecimal(value: Float): String {
        return if (value % 1f == 0f) {
            value.toInt().toString()
        } else {
            String.format(Locale.US, "%.1f", value)
        }
    }

    // --- SOC / Chipset helpers ---

    private fun readSocManufacturer(): String? {
        // API 31+ (Android 12+) provides Build.SOC_MANUFACTURER
        return runCatching {
            Build::class.java.getDeclaredField("SOC_MANUFACTURER").let { field ->
                field.isAccessible = true
                field.get(null) as? String
            }
        }.getOrNull()
    }

    private fun readSocModel(): String? {
        // API 31+ (Android 12+) provides Build.SOC_MODEL
        return runCatching {
            Build::class.java.getDeclaredField("SOC_MODEL").let { field ->
                field.isAccessible = true
                field.get(null) as? String
            }
        }.getOrNull()
    }

    private fun readCpuHardware(): String? {
        // Try parsing /proc/cpuinfo for "Hardware" line first
        runCatching {
            File("/proc/cpuinfo").useLines { lines ->
                lines.firstOrNull { it.startsWith("Hardware") }
                    ?.substringAfter(":")
                    ?.trim()
                    ?.takeIf { it.isNotEmpty() }
            }
        }.getOrNull()?.let { return it }

        // Fallback: use Build.HARDWARE if not available via cpuinfo
        return Build.HARDWARE.takeIf { it.isNotBlank() }
    }

    @Suppress("PrivateApi")
    private fun readSystemProperty(name: String): String? {
        // Try Android hidden API reflection first
        runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, name) as? String)?.trim()?.takeIf { it.isNotEmpty() }
        }.getOrNull()?.let { return it }

        // Fallback: use getprop shell command
        return readViaGetprop(name)
    }

    private fun readViaGetprop(name: String): String? {
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

    private fun checkIsolatedProcessSupport(): String {
        // Isolated processes were introduced in API 16 (Android 4.1).
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN) {
            return "Unsupported (API < 16)"
        }

        // Verify the platform recognizes the FLAG_ISOLATED_PROCESS constant.
        val flagDefined = runCatching {
            ServiceInfo::class.java.getDeclaredField("FLAG_ISOLATED_PROCESS")
        }.isSuccess

        if (!flagDefined) {
            return "Unavailable (flag missing)"
        }

        // Check if the ActivityManager can enumerate isolated processes.
        val activityManager =
            appContext.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        if (activityManager != null) {
            val canList = runCatching {
                // Some restricted environments block getRunningAppProcesses.
                activityManager.runningAppProcesses
            }.isSuccess
            if (!canList) {
                return "Supported (restricted visibility)"
            }
        }

        return "Supported"
    }

    private companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 3L
    }
}
