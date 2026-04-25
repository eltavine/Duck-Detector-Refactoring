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

import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.Display
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoEntry
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoReport
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoSection
import com.eltavine.duckdetector.features.deviceinfo.domain.DeviceInfoStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale
import java.util.TimeZone

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
}
