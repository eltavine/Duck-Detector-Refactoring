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
import android.util.Log
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.features.crashreport.domain.CrashReport
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Registers a global uncaught exception handler that captures device context
 * and writes a crash report to disk before delegating to the system default
 * handler.
 *
 * Usage — call once during Application.onCreate():
 * ```
 * CrashHandler.install(applicationContext)
 * ```
 *
 * To retrieve the last crash report after a restart:
 * ```
 * val lastCrash: CrashReport? = CrashHandler.lastCrashReport(context)
 * ```
 */
object CrashHandler {

    private const val TAG = "DuckCrashHandler"
    private const val CRASH_DIR = "crash_reports"
    private const val CRASH_FILE_PREFIX = "crash_"
    private const val MAX_CRASH_FILES = 5

    // Startup tracking: detects crashes that happen before the UI fully loads
    private const val MARKER_LAUNCH_STARTED = "launch_started.marker"
    private const val MARKER_LAUNCH_COMPLETED = "launch_completed.marker"
    private const val MARKER_LAST_CRASH = "last_crash_time.marker"

    private var originalHandler: Thread.UncaughtExceptionHandler? = null
    private var appContext: Context? = null

    /**
     * Install the crash handler. Safe to call multiple times — duplicates are ignored.
     */
    @Synchronized
    fun install(context: Context) {
        if (originalHandler != null) return

        appContext = context.applicationContext
        val current = Thread.getDefaultUncaughtExceptionHandler()

        // Avoid chaining ourselves
        if (current is DuckUncaughtHandler) return

        originalHandler = current
        Thread.setDefaultUncaughtExceptionHandler(
            DuckUncaughtHandler(current, context.applicationContext),
        )

        Log.d(TAG, "Crash handler installed (previous=${originalHandler?.javaClass?.simpleName})")
    }

    /**
     * Returns the most recent [CrashReport] that was persisted to disk, or null.
     */
    fun lastCrashReport(context: Context): CrashReport? {
        return runCatching {
            val dir = crashDir(context)
            val latestFile = dir.listFiles()
                ?.filter { it.name.startsWith(CRASH_FILE_PREFIX) && it.extension == "txt" }
                ?.maxByOrNull { it.lastModified() }
            latestFile?.let { parseCrashFile(it) }
        }.getOrNull()
    }

    /**
     * Returns all persisted crash report files, sorted newest first.
     */
    fun listCrashFiles(context: Context): List<File> {
        return runCatching {
            val dir = crashDir(context)
            dir.listFiles()
                ?.filter { it.name.startsWith(CRASH_FILE_PREFIX) && it.extension == "txt" }
                ?.sortedByDescending { it.lastModified() }
                .orEmpty()
        }.getOrDefault(emptyList())
    }

    /**
     * Delete all crash report files.
     */
    fun clearAll(context: Context) {
        runCatching {
            crashDir(context).listFiles()?.forEach { it.delete() }
            clearMarkers(context)
        }
    }

    // --- Startup crash tracking ---

    /**
     * Call at the earliest safe point in app startup (e.g., Application.onCreate).
     * Pairs with [markLaunchCompleted] to detect startup crashes.
     */
    fun markLaunchStarted(context: Context) {
        runCatching {
            val marker = File(markerDir(context), MARKER_LAUNCH_STARTED)
            marker.writeText(System.currentTimeMillis().toString(), Charsets.UTF_8)
        }
    }

    /**
     * Call when the app UI is fully loaded (e.g., DashboardScreen first composition).
     * Pairs with [markLaunchStarted] to detect startup crashes.
     */
    fun markLaunchCompleted(context: Context) {
        runCatching {
            val marker = File(markerDir(context), MARKER_LAUNCH_COMPLETED)
            marker.writeText(System.currentTimeMillis().toString(), Charsets.UTF_8)
        }
    }

    /**
     * Returns true if the previous launch appears to have crashed before
     * the UI fully loaded (i.e., a startup crash / "app won't open" scenario).
     */
    fun wasStartupCrash(context: Context): Boolean {
        return runCatching {
            val startedFile = File(markerDir(context), MARKER_LAUNCH_STARTED)
            val completedFile = File(markerDir(context), MARKER_LAUNCH_COMPLETED)
            val crashMarkerFile = File(markerDir(context), MARKER_LAST_CRASH)

            // If no launch was ever started, nothing to detect
            if (!startedFile.exists()) return false

            val startedTime = startedFile.readText(Charsets.UTF_8).toLongOrNull() ?: return false
            val completedTime = completedFile.takeIf { it.exists() }
                ?.readText(Charsets.UTF_8)?.toLongOrNull()

            val lastCrashTime = crashMarkerFile.takeIf { it.exists() }
                ?.readText(Charsets.UTF_8)?.toLongOrNull()

            // Scenario 1: started marker exists but completed marker doesn't → never finished launching
            if (completedTime == null) return true

            // Scenario 2: last crash time is newer than completed time → crashed after previous completion
            if (lastCrashTime != null && lastCrashTime > completedTime) return true

            // Scenario 3: started time is newer than completed time → started again but never finished
            if (startedTime > completedTime) return true

            false
        }.getOrDefault(false)
    }

    /**
     * Returns the most recent crash file that is accessible without root/adb
     * (written to external cache directory).
     */
    fun latestExternalCrashFile(context: Context): File? {
        return runCatching {
            val dir = externalCrashDir(context)
            dir.listFiles()
                ?.filter { it.name.startsWith(CRASH_FILE_PREFIX) && it.extension == "txt" }
                ?.maxByOrNull { it.lastModified() }
        }.getOrNull()
    }

    /**
     * Write a minimal sentinel crash report even when the full collector fails.
     * This guarantees *something* is written when the app crashes during
     * startup and the full device-info collection path is unavailable.
     */
    fun writeMinimalCrash(context: Context, throwable: Throwable) {
        runCatching {
            val now = System.currentTimeMillis()
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date(now))
            val fileName = "${CRASH_FILE_PREFIX}${timestamp}_minimal.txt"

            val content = buildString {
                appendLine("=== Duck Detector — MINIMAL CRASH REPORT ===")
                appendLine("Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date(now))}")
                appendLine("Exception: ${throwable.javaClass.name}")
                appendLine("Message: ${throwable.message ?: "(no message)"}")
                appendLine()
                appendLine("Stack trace:")
                throwable.stackTrace.take(40).forEach { frame ->
                    appendLine("  at $frame")
                }
            }

            // Write to internal storage
            val internalFile = File(crashDir(context), fileName)
            internalFile.writeText(content, Charsets.UTF_8)

            // Also write to external cache if available
            runCatching {
                val externalFile = File(externalCrashDir(context), fileName)
                externalFile.writeText(content, Charsets.UTF_8)
            }

            // Update last crash marker
            runCatching {
                File(markerDir(context), MARKER_LAST_CRASH)
                    .writeText(now.toString(), Charsets.UTF_8)
            }

            // Evict old files
            evictOldFiles(crashDir(context))
            runCatching {
                evictOldFiles(externalCrashDir(context))
            }

            Log.e(TAG, "Minimal crash report written", throwable)
        }
    }

    private fun clearMarkers(context: Context) {
        runCatching {
            val dir = markerDir(context)
            File(dir, MARKER_LAUNCH_STARTED).delete()
            File(dir, MARKER_LAUNCH_COMPLETED).delete()
            File(dir, MARKER_LAST_CRASH).delete()
        }
    }

    // --- Internal handler class ---

    private class DuckUncaughtHandler(
        private val defaultHandler: Thread.UncaughtExceptionHandler?,
        private val context: Context,
    ) : Thread.UncaughtExceptionHandler {

        override fun uncaughtException(thread: Thread, throwable: Throwable) {
            // 1. Collect crash report defensively — full collection first
            val collected = runCatching {
                val report = CrashCollector.collect(context, throwable)
                persistReport(context, report)
                Log.e(TAG, "Crash captured: ${report.exceptionClassName}", throwable)
                true
            }.getOrElse { persistError ->
                Log.e(TAG, "Full crash collection failed — writing minimal report", persistError)
                false
            }

            // 2. Fallback: if full collection failed, write a minimal crash report
            if (!collected) {
                runCatching {
                    writeMinimalCrash(context, throwable)
                }.getOrElse { minimalError ->
                    Log.e(TAG, "Even minimal crash report failed", minimalError)
                }
            }

            // 3. Delegate to the original handler (which will kill the process)
            defaultHandler?.uncaughtException(thread, throwable)
                ?: run {
                    Log.e(TAG, "No default handler — killing process")
                    android.os.Process.killProcess(android.os.Process.myPid())
                    System.exit(10)
                }
        }
    }

    // --- Persistence ---

    private fun persistReport(context: Context, report: CrashReport) {
        runCatching {
            val dir = crashDir(context)
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(
                Date(report.crashTimeUtcMillis),
            )
            val fileName = "${CRASH_FILE_PREFIX}${timestamp}.txt"
            val content = CrashReportFormatter.format(report)

            // Write to internal storage
            val internalFile = File(dir, fileName)
            internalFile.writeText(content, Charsets.UTF_8)

            // Also write to external cache for user accessibility
            runCatching {
                val externalDir = externalCrashDir(context)
                val externalFile = File(externalDir, fileName)
                externalFile.writeText(content, Charsets.UTF_8)
            }

            // Update last crash time marker
            runCatching {
                File(markerDir(context), MARKER_LAST_CRASH)
                    .writeText(report.crashTimeUtcMillis.toString(), Charsets.UTF_8)
            }

            // Evict oldest files if exceeding max
            evictOldFiles(dir)
            runCatching { evictOldFiles(externalCrashDir(context)) }
        }
    }

    private fun evictOldFiles(dir: File) {
        runCatching {
            val crashFiles = dir.listFiles()
                ?.filter { it.name.startsWith(CRASH_FILE_PREFIX) && it.extension == "txt" }
                ?.sortedBy { it.lastModified() }
                .orEmpty()

            if (crashFiles.size > MAX_CRASH_FILES) {
                crashFiles.take(crashFiles.size - MAX_CRASH_FILES).forEach { it.delete() }
            }
        }
    }

    private fun crashDir(context: Context): File {
        val dir = File(context.filesDir, CRASH_DIR)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun externalCrashDir(context: Context): File {
        val dir = File(context.externalCacheDir ?: context.cacheDir, CRASH_DIR)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun markerDir(context: Context): File {
        val dir = File(context.filesDir, "crash_markers")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    // --- Deserialization (lightweight — no JSON needed) ---

    private fun parseCrashFile(file: File): CrashReport? {
        return runCatching {
            val text = file.readText(Charsets.UTF_8)
            val lines = text.lines()

            var crashTimeUtcMillis = 0L
            var crashTimeIso = ""
            var appVersionName = ""
            var appVersionCode = 0L
            var appBuildHash = ""
            var appBuildTimeUtc = ""
            val deviceSections = mutableListOf<CrashDeviceSection>()
            var exceptionClassName = ""
            var exceptionMessage = ""
            var stackTrace = ""
            var threadName = ""
            var processName = ""
            var pid = 0
            val causeChain = mutableListOf<String>()

            var currentSection: String? = null
            var currentSectionEntries = mutableListOf<CrashDeviceEntry>()
            var inStackTrace = false
            val stackTraceLines = mutableListOf<String>()

            for (line in lines) {
                val trimmed = line.trim()

                when {
                    trimmed.startsWith("Crash Time (UTC) : ") -> {
                        crashTimeIso = trimmed.substringAfter(": ").trim()
                    }
                    trimmed.startsWith("Crash Time (local): ") -> {
                        // local time, keep UTC millis via file timestamp
                        crashTimeUtcMillis = file.lastModified()
                    }
                    trimmed.startsWith("Version    : ") -> {
                        val v = trimmed.substringAfter(": ").trim()
                        val parts = v.split(" (")
                        appVersionName = parts.getOrElse(0) { "" }
                        appVersionCode = parts.getOrElse(1) { "0" }.removeSuffix(")").toLongOrNull() ?: 0L
                    }
                    trimmed.startsWith("Build Hash : ") -> {
                        appBuildHash = trimmed.substringAfter(": ").trim()
                    }
                    trimmed.startsWith("Build Time : ") -> {
                        appBuildTimeUtc = trimmed.substringAfter(": ").trim()
                    }
                    trimmed.startsWith("Thread  : ") -> {
                        threadName = trimmed.substringAfter(": ").trim()
                    }
                    trimmed.startsWith("Process : ") -> {
                        processName = trimmed.substringAfter(": ").trim()
                    }
                    trimmed.startsWith("PID     : ") -> {
                        pid = trimmed.substringAfter(": ").trim().toIntOrNull() ?: 0
                    }
                    trimmed.startsWith("Class   : ") -> {
                        exceptionClassName = trimmed.substringAfter(": ").trim()
                    }
                    trimmed.startsWith("Message : ") -> {
                        exceptionMessage = trimmed.substringAfter(": ").trim()
                    }
                    trimmed == "----- CAUSE CHAIN -----" -> {
                        currentSection = "cause"
                    }
                    trimmed == "----- STACK TRACE -----" -> {
                        // Flush previous section
                        if (currentSection != null && currentSection !in listOf("cause", "stack")) {
                            deviceSections.add(
                                CrashDeviceSection(
                                    title = currentSection ?: "Unknown",
                                    entries = currentSectionEntries.toList(),
                                ),
                            )
                        }
                        currentSection = "stack"
                        currentSectionEntries.clear()
                        inStackTrace = true
                    }
                    trimmed.matches(Regex("""^----- .+ -----$""")) && !trimmed.startsWith("----- CAUSE") && !trimmed.startsWith("----- STACK") -> {
                        // Flush previous section
                        if (currentSection != null && currentSection !in listOf("cause", "stack")) {
                            deviceSections.add(
                                CrashDeviceSection(
                                    title = currentSection ?: "Unknown",
                                    entries = currentSectionEntries.toList(),
                                ),
                            )
                        }
                        currentSection = trimmed.removePrefix("----- ").removeSuffix(" -----")
                        currentSectionEntries = mutableListOf()
                        inStackTrace = false
                    }
                    inStackTrace -> {
                        stackTraceLines.add(line)
                    }
                    trimmed.startsWith("  [") && currentSection == "cause" -> {
                        causeChain.add(trimmed.replace(Regex("""^  \[\d+\] """), ""))
                    }
                    trimmed.contains(": ") && currentSection != null && currentSection != "cause" && currentSection != "stack" && !inStackTrace -> {
                        val colon = trimmed.indexOf(": ")
                        if (colon > 0) {
                            currentSectionEntries.add(
                                CrashDeviceEntry(
                                    label = trimmed.substring(0, colon).trimStart(),
                                    value = trimmed.substring(colon + 2).trim(),
                                ),
                            )
                        }
                    }
                }
            }

            // Flush last section
            if (currentSection != null && currentSection != "cause" && currentSection != "stack") {
                deviceSections.add(
                    CrashDeviceSection(
                        title = currentSection ?: "Unknown",
                        entries = currentSectionEntries.toList(),
                    ),
                )
            }

            stackTrace = stackTraceLines.joinToString("\n")

            CrashReport(
                crashTimeUtcMillis = crashTimeUtcMillis,
                crashTimeIso = crashTimeIso,
                appVersionName = appVersionName,
                appVersionCode = appVersionCode,
                appBuildHash = appBuildHash,
                appBuildTimeUtc = appBuildTimeUtc,
                deviceSections = deviceSections,
                exceptionClassName = exceptionClassName,
                exceptionMessage = exceptionMessage,
                stackTrace = stackTrace,
                threadName = threadName,
                processName = processName,
                pid = pid,
                causeChain = causeChain,
            )
        }.getOrNull()
    }
}
