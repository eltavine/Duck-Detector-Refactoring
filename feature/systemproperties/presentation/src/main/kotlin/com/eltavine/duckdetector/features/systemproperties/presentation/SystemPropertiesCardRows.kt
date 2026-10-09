/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.systemproperties.presentation

import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySource
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.systemproperties.domain.PropertyAreaClocks
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.presentation.model.SystemPropertiesDetailRowModel

internal fun buildCoreRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
    return when (report.stage) {
        SystemPropertiesStage.LOADING -> placeholderRows(
            labels = listOf(
                "ro.secure",
                "ro.debuggable",
                "service.adb.root",
                "init.svc.magisk_daemon"
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        SystemPropertiesStage.FAILED -> placeholderRows(
            labels = listOf(
                "ro.secure",
                "ro.debuggable",
                "service.adb.root",
                "init.svc.magisk_daemon"
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        SystemPropertiesStage.READY -> report.signals.filter {
            it.category == SystemPropertyCategory.SECURITY_CORE ||
                    it.category == SystemPropertyCategory.ROOT_RUNTIME ||
                    it.category == SystemPropertyCategory.CUSTOM_ROM
        }.sortedBy { it.property }
            .map(::signalRow)
    }
}

internal fun buildBootRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
    return when (report.stage) {
        SystemPropertiesStage.LOADING -> placeholderRows(
            labels = listOf(
                "ro.boot.verifiedbootstate",
                "ro.boot.flash.locked",
                "partition.system.verified"
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        SystemPropertiesStage.FAILED -> placeholderRows(
            labels = listOf(
                "ro.boot.verifiedbootstate",
                "ro.boot.flash.locked",
                "partition.system.verified"
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        SystemPropertiesStage.READY -> report.signals.filter {
            it.category == SystemPropertyCategory.VERIFIED_BOOT ||
                    it.category == SystemPropertyCategory.PARTITION_VERITY
        }.sortedBy { it.property }
            .map(::signalRow)
    }
}

internal fun buildBuildRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
    return when (report.stage) {
        SystemPropertiesStage.LOADING -> placeholderRows(
            labels = listOf(
                "ro.build.type",
                "ro.build.tags",
                "Build.TAGS",
                "Build.FINGERPRINT"
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
        )

        SystemPropertiesStage.FAILED -> placeholderRows(
            labels = listOf(
                "ro.build.type",
                "ro.build.tags",
                "Build.TAGS",
                "Build.FINGERPRINT"
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
        )

        SystemPropertiesStage.READY -> report.signals.filter {
            it.category == SystemPropertyCategory.BUILD_PROFILE
        }.sortedBy { it.property }
            .map(::signalRow)
    }
}

internal fun buildSourceRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
    return when (report.stage) {
        SystemPropertiesStage.LOADING -> placeholderRows(
            labels = listOf("ro.boot.verifiedbootstate", "ro.build.type"),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
            monospace = true,
        )

        SystemPropertiesStage.FAILED -> placeholderRows(
            labels = listOf("ro.boot.verifiedbootstate", "ro.build.type"),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
            monospace = true,
        )

        SystemPropertiesStage.READY -> report.signals.filter {
            it.category == SystemPropertyCategory.SOURCE_CONSISTENCY
        }.sortedBy { it.property }
            .map(::signalRow)
    }
}

internal fun buildConsistencyRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
    return when (report.stage) {
        SystemPropertiesStage.LOADING -> placeholderRows(
            labels = listOf(
                "Verified boot coherence",
                "Build.TYPE <> fingerprint tail",
                "prop_area hole: u:object_r:shell_prop:s0"
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
            monospace = true,
        )

        SystemPropertiesStage.FAILED -> placeholderRows(
            labels = listOf(
                "Verified boot coherence",
                "Build.TYPE <> fingerprint tail",
                "prop_area hole: u:object_r:shell_prop:s0"
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
            monospace = true,
        )

        SystemPropertiesStage.READY -> {
            val rows = report.signals.filter {
                it.category == SystemPropertyCategory.PROPERTY_CONSISTENCY
            }.sortedBy { it.property }
                .map(::signalRow)
            val clocks = report.propertyAreaClocks ?: return rows
            rows + propertyAreaAnomalyRow(clocks)
        }
    }
}

private fun propertyAreaAnomalyRow(clocks: PropertyAreaClocks): SystemPropertiesDetailRowModel {
    return when (clocks) {
        is PropertyAreaClocks.Ordered -> SystemPropertiesDetailRowModel(
            label = "Device property-area anomaly",
            value = clocks.debugMinusRadioNanos.toString(),
            status = DetectorStatus.warning(),
            detail = "Nanoseconds from the radio property area's modification time to the debug area's. " +
                "Shown because the system area is newer than debug, and debug is newer than radio.",
            detailMonospace = true,
        )

        PropertyAreaClocks.NotOrdered -> SystemPropertiesDetailRowModel(
            label = "Device property-area anomaly",
            value = "Clean",
            status = DetectorStatus.allClear(),
            detail = "The debug, system and radio property areas were read. " +
                "System newer than debug and debug newer than radio did not hold.",
            detailMonospace = true,
        )

        PropertyAreaClocks.Unreadable -> SystemPropertiesDetailRowModel(
            label = "Device property-area anomaly",
            value = "Unavailable",
            status = DetectorStatus.info(InfoKind.SUPPORT),
            detail = "At least one of the debug, system and radio property areas could not be stat'ed from this app, " +
                "so their modification times were not compared.",
            detailMonospace = true,
        )
    }
}

internal fun buildInfoRows(report: SystemPropertiesReport): List<SystemPropertiesDetailRowModel> {
    return when (report.stage) {
        SystemPropertiesStage.LOADING -> placeholderRows(
            labels = listOf(
                "ro.product.model",
                "ro.build.version.security_patch",
                "ro.build.fingerprint"
            ),
            status = DetectorStatus.info(InfoKind.SUPPORT),
            value = "Pending",
            monospace = true,
        )

        SystemPropertiesStage.FAILED -> placeholderRows(
            labels = listOf(
                "ro.product.model",
                "ro.build.version.security_patch",
                "ro.build.fingerprint"
            ),
            status = DetectorStatus.info(InfoKind.ERROR),
            value = "Error",
            monospace = true,
        )

        SystemPropertiesStage.READY -> report.infoSignals.sortedBy { it.property }
            .map(::infoRow)
    }
}

private fun signalRow(signal: SystemPropertySignal): SystemPropertiesDetailRowModel {
    val detailLines = buildList {
        add(signal.description)
        add("Source: ${sourceLabel(signal.source)}")
        add("Observed: ${signal.value}")
        signal.detail
            ?.takeIf { it.isNotBlank() && !it.equals(signal.description, ignoreCase = true) }
            ?.let { add(it) }
    }
    return SystemPropertiesDetailRowModel(
        label = signal.property,
        value = badgeValue(signal.value),
        status = signalStatus(signal),
        detail = detailLines.joinToString(separator = "\n"),
        detailMonospace = true,
    )
}

private fun infoRow(signal: SystemPropertySignal): SystemPropertiesDetailRowModel {
    return SystemPropertiesDetailRowModel(
        label = signal.description,
        value = badgeValue(signal.value),
        status = DetectorStatus.info(InfoKind.SUPPORT),
        detail = buildString {
            append(signal.property)
            appendLine()
            append("Source: ")
            append(sourceLabel(signal.source))
            appendLine()
            append(signal.value)
        },
        detailMonospace = true,
    )
}

internal fun placeholderRows(
    labels: List<String>,
    status: DetectorStatus,
    value: String,
    monospace: Boolean = false,
): List<SystemPropertiesDetailRowModel> {
    return labels.map { label ->
        SystemPropertiesDetailRowModel(
            label = label,
            value = value,
            status = status,
            detailMonospace = monospace,
        )
    }
}

private fun badgeValue(
    value: String,
): String {
    return if (value.length > MAX_BADGE_LENGTH) {
        value.take(MAX_BADGE_LENGTH - 1) + "…"
    } else {
        value
    }
}

private fun sourceLabel(
    source: SystemPropertySource,
): String {
    return when (source) {
        SystemPropertySource.REFLECTION -> "Reflection"
        SystemPropertySource.GETPROP -> "getprop"
        SystemPropertySource.JVM -> "System.getProperty"
        SystemPropertySource.BUILD -> "Build constant"
        SystemPropertySource.NATIVE_LIBC -> "Native libc"
        SystemPropertySource.CMDLINE -> "/proc/cmdline"
        SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
    }
}

private fun signalStatus(
    signal: SystemPropertySignal,
): DetectorStatus {
    return when (signal.severity) {
        SystemPropertySeverity.SAFE -> DetectorStatus.allClear()
        SystemPropertySeverity.WARNING -> DetectorStatus.warning()
        SystemPropertySeverity.DANGER -> DetectorStatus.danger()
        SystemPropertySeverity.NEUTRAL -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

private const val MAX_BADGE_LENGTH = 18
