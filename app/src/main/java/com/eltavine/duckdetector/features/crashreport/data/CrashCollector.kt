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

package com.eltavine.duckdetector.features.crashreport.data

import android.content.Context
import android.os.Build
import android.os.Process as AndroidProcess
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.crashreport.domain.CrashDeviceEntry
import com.eltavine.duckdetector.features.crashreport.domain.CrashDeviceSection
import com.eltavine.duckdetector.features.crashreport.domain.CrashReport
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

/**
 * Collects device information and crash details at the moment of an uncaught exception.
 *
 * All collection is wrapped defensively — a failure inside the crash handler
 * must never prevent the original exception from reaching the default handler.
 */
internal object CrashCollector {

    private const val PROCESS_TIMEOUT_SECONDS = 2L

    fun collect(context: Context, throwable: Throwable): CrashReport {
        val now = System.currentTimeMillis()
        val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }

        return CrashReport(
            crashTimeUtcMillis = now,
            crashTimeIso = isoFormat.format(Date(now)),
            appVersionName = safeString { BuildConfig.VERSION_NAME },
            appVersionCode = BuildConfig.VERSION_CODE.toLong(),
            appBuildHash = safeString { BuildConfig.BUILD_HASH },
            appBuildTimeUtc = safeString { formatBuildTimeUtc(BuildConfig.BUILD_TIME_UTC) },
            deviceSections = collectDeviceSections(),
            exceptionClassName = throwable.javaClass.name,
            exceptionMessage = throwable.message ?: "(no message)",
            stackTrace = stackTraceToString(throwable),
            threadName = safeString { Thread.currentThread().name },
            processName = safeString { getProcessName() },
            pid = AndroidProcess.myPid(),
            causeChain = collectCauseChain(throwable),
        )
    }

    // --- Device info collection ---

    private fun collectDeviceSections(): List<CrashDeviceSection> {
        return listOf(
            collectIdentitySection(),
            collectSocSection(),
            collectBuildSection(),
            collectAndroidSection(),
            collectRuntimeSection(),
        )
    }

    private fun collectIdentitySection(): CrashDeviceSection {
        return CrashDeviceSection(
            title = "Identity",
            entries = listOf(
                CrashDeviceEntry("Brand", Build.BRAND.orUnavailable()),
                CrashDeviceEntry("Manufacturer", Build.MANUFACTURER.orUnavailable()),
                CrashDeviceEntry("Model", Build.MODEL.orUnavailable()),
                CrashDeviceEntry("Device", Build.DEVICE.orUnavailable()),
                CrashDeviceEntry("Product", Build.PRODUCT.orUnavailable()),
                CrashDeviceEntry("Board", Build.BOARD.orUnavailable()),
            ),
        )
    }

    private fun collectSocSection(): CrashDeviceSection {
        return CrashDeviceSection(
            title = "SOC / Chipset",
            entries = listOf(
                CrashDeviceEntry("SOC Manufacturer", readSocManufacturer().orUnavailable()),
                CrashDeviceEntry("SOC Model", readSocModel().orUnavailable()),
                CrashDeviceEntry("CPU Hardware", readCpuHardware().orUnavailable()),
                CrashDeviceEntry("Board Platform", readProp("ro.board.platform").orUnavailable()),
                CrashDeviceEntry("Chip Name", readProp("ro.chipname").orUnavailable()),
                CrashDeviceEntry("CPU Cores", Runtime.getRuntime().availableProcessors().toString()),
                CrashDeviceEntry("CPU Arch", safeString { System.getProperty("os.arch") }.orUnavailable()),
                CrashDeviceEntry("ABI List", Build.SUPPORTED_ABIS.joinToString().orUnavailable()),
            ),
        )
    }

    private fun collectBuildSection(): CrashDeviceSection {
        return CrashDeviceSection(
            title = "Build",
            entries = listOf(
                CrashDeviceEntry("Hardware", Build.HARDWARE.orUnavailable()),
                CrashDeviceEntry("Bootloader", Build.BOOTLOADER.orUnavailable()),
                CrashDeviceEntry("Fingerprint", Build.FINGERPRINT.orUnavailable()),
                CrashDeviceEntry("Build ID", Build.ID.orUnavailable()),
                CrashDeviceEntry("Incremental", Build.VERSION.INCREMENTAL.orUnavailable()),
                CrashDeviceEntry("Build type", Build.TYPE.orUnavailable()),
            ),
        )
    }

    private fun collectAndroidSection(): CrashDeviceSection {
        return CrashDeviceSection(
            title = "Android",
            entries = listOf(
                CrashDeviceEntry("Tags", Build.TAGS.orUnavailable()),
                CrashDeviceEntry("Build user", Build.USER.orUnavailable()),
                CrashDeviceEntry("Build host", Build.HOST.orUnavailable()),
                CrashDeviceEntry("SDK", Build.VERSION.SDK_INT.toString()),
                CrashDeviceEntry("Release", Build.VERSION.RELEASE.orUnavailable()),
                CrashDeviceEntry("Codename", Build.VERSION.CODENAME.orUnavailable()),
            ),
        )
    }

    private fun collectRuntimeSection(): CrashDeviceSection {
        return CrashDeviceSection(
            title = "Runtime",
            entries = listOf(
                CrashDeviceEntry("Security patch", Build.VERSION.SECURITY_PATCH.orUnavailable()),
                CrashDeviceEntry("Primary ABI", Build.SUPPORTED_ABIS.firstOrNull().orUnavailable()),
                CrashDeviceEntry("Kernel", safeString { System.getProperty("os.version") }.orUnavailable()),
                CrashDeviceEntry("Locale", Locale.getDefault().toLanguageTag()),
                CrashDeviceEntry("Time zone", TimeZone.getDefault().id),
            ),
        )
    }

    // --- Stack trace helpers ---

    private fun stackTraceToString(throwable: Throwable): String {
        return safeString {
            StringWriter().use { sw ->
                PrintWriter(sw).use { pw ->
                    throwable.printStackTrace(pw)
                    sw.toString()
                }
            }
        }
    }

    private fun collectCauseChain(throwable: Throwable): List<String> {
        val chain = mutableListOf<String>()
        var cause: Throwable? = throwable.cause
        while (cause != null && chain.size < 10) {
            chain.add("${cause.javaClass.name}: ${cause.message ?: "(no message)"}")
            cause = cause.cause
        }
        return chain
    }

    // --- SOC / property helpers ---

    private fun readSocManufacturer(): String? {
        return runCatching {
            Build::class.java.getDeclaredField("SOC_MANUFACTURER").let { f ->
                f.isAccessible = true
                f.get(null) as? String
            }
        }.getOrNull()
    }

    private fun readSocModel(): String? {
        return runCatching {
            Build::class.java.getDeclaredField("SOC_MODEL").let { f ->
                f.isAccessible = true
                f.get(null) as? String
            }
        }.getOrNull()
    }

    private fun readCpuHardware(): String? {
        runCatching {
            File("/proc/cpuinfo").useLines { lines ->
                lines.firstOrNull { it.startsWith("Hardware") }
                    ?.substringAfter(":")
                    ?.trim()
                    ?.takeIf { it.isNotEmpty() }
            }
        }.getOrNull()?.let { return it }
        return Build.HARDWARE.takeIf { it.isNotBlank() }
    }

    @Suppress("PrivateApi")
    private fun readProp(name: String): String? {
        runCatching {
            val clazz = Class.forName("android.os.SystemProperties")
            val method = clazz.getMethod("get", String::class.java)
            (method.invoke(null, name) as? String)?.trim()?.takeIf { it.isNotEmpty() }
        }.getOrNull()?.let { return it }

        return readViaGetprop(name)
    }

    private fun readViaGetprop(name: String): String? {
        var process: java.lang.Process? = null
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

    private fun getProcessName(): String {
        return safeString {
            runCatching {
                val method = Class.forName("android.os.Process")
                    .getMethod("getProcessName")
                (method.invoke(null) as? String) ?: "Unknown"
            }.getOrNull() ?: "Unknown"
        }
    }

    // --- Safety wrappers ---

    private fun String?.orUnavailable(): String {
        return this?.trim()?.takeIf { it.isNotEmpty() } ?: "Unavailable"
    }

    private fun safeString(block: () -> String): String {
        return runCatching { block() }.getOrDefault("Unavailable")
    }
}
