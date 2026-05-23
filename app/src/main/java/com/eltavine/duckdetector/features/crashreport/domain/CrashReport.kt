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

package com.eltavine.duckdetector.features.crashreport.domain

/**
 * Represents a collected crash report with full device context.
 */
data class CrashReport(
    val crashTimeUtcMillis: Long,
    val crashTimeIso: String,
    val appVersionName: String,
    val appVersionCode: Long,
    val appBuildHash: String,
    val appBuildTimeUtc: String,
    val deviceSections: List<CrashDeviceSection>,
    val exceptionClassName: String,
    val exceptionMessage: String,
    val stackTrace: String,
    val threadName: String,
    val processName: String,
    val pid: Int,
    val causeChain: List<String>,
) {
    val totalDeviceFacts: Int
        get() = deviceSections.sumOf { it.entries.size }
}

data class CrashDeviceSection(
    val title: String,
    val entries: List<CrashDeviceEntry>,
)

data class CrashDeviceEntry(
    val label: String,
    val value: String,
)
