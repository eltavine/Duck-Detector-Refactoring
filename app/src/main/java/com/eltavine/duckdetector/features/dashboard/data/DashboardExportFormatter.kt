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

package com.eltavine.duckdetector.features.dashboard.data

import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderCardModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomCardModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorCardEntry
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardUiState
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.kernelcheck.ui.model.KernelCheckCardModel
import com.eltavine.duckdetector.features.lsposed.ui.model.LSPosedCardModel
import com.eltavine.duckdetector.features.memory.ui.model.MemoryCardModel
import com.eltavine.duckdetector.features.mount.ui.model.MountCardModel
import com.eltavine.duckdetector.features.nativeroot.ui.model.NativeRootCardModel
import com.eltavine.duckdetector.features.playintegrityfix.ui.model.PlayIntegrityFixCardModel
import com.eltavine.duckdetector.features.selinux.ui.model.SelinuxCardModel
import com.eltavine.duckdetector.features.su.ui.model.SuCardModel
import com.eltavine.duckdetector.features.systemproperties.ui.model.SystemPropertiesCardModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeCardModel
import com.eltavine.duckdetector.features.virtualization.ui.model.VirtualizationCardModel
import com.eltavine.duckdetector.features.zygisk.ui.model.ZygiskCardModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DashboardExportFormatter {

    fun format(state: DashboardUiState): String = buildString {
        appendLine("========================================")
        appendLine("  Duck Detector — Security Scan Report")
        appendLine("========================================")
        appendLine()
        appendLine("App Version : ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
        appendLine("Build Hash  : ${BuildConfig.BUILD_HASH}")
        appendLine("Build Time  : ${formatBuildTimeUtc(BuildConfig.BUILD_TIME_UTC)} (UTC)")
        appendLine("Report Time : ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss (z)", Locale.US).format(Date())}")
        appendLine()

        appendLine("----- OVERVIEW -----")
        appendLine("Status  : ${state.overview.headline}")
        appendLine("Summary : ${state.overview.summary}")
        appendLine()
        appendLine("Metrics:")
        state.overview.metrics.forEach { metric ->
            appendLine("  ${metric.label}: ${metric.value}")
        }
        appendLine()

        appendLine("----- TOP FINDINGS -----")
        if (state.topFindings.isEmpty()) {
            appendLine("  (none)")
        } else {
            state.topFindings.forEach { finding ->
                val severity = severityLabel(finding.status.severity)
                appendLine("  [$severity] ${finding.detectorTitle}")
                appendLine("    ${finding.headline}")
                appendLine("    ${finding.detail}")
            }
        }
        appendLine()

        appendLine("----- DETECTOR CARDS -----")
        state.detectorCards.forEach { entry ->
            appendDetectorCard(entry)
        }
        appendLine()

        appendLine("----- DEVICE INFO -----")
        appendDeviceInfo(state.deviceInfoCard)
        appendLine()

        appendLine("========================================")
        appendLine("  End of report")
        appendLine("========================================")
    }

    private fun StringBuilder.appendDetectorCard(entry: DashboardDetectorCardEntry) {
        when (entry) {
            is DashboardDetectorCardEntry.Bootloader -> appendBootloader(entry.model)
            is DashboardDetectorCardEntry.Mount -> appendMount(entry.model)
            is DashboardDetectorCardEntry.CustomRom -> appendCustomRom(entry.model)
            is DashboardDetectorCardEntry.Selinux -> appendSelinux(entry.model)
            is DashboardDetectorCardEntry.DangerousApps -> appendDangerousApps(entry.model)
            is DashboardDetectorCardEntry.KernelCheck -> appendKernelCheck(entry.model)
            is DashboardDetectorCardEntry.Memory -> appendMemory(entry.model)
            is DashboardDetectorCardEntry.LSPosed -> appendLSPosed(entry.model)
            is DashboardDetectorCardEntry.NativeRoot -> appendNativeRoot(entry.model)
            is DashboardDetectorCardEntry.PlayIntegrityFix -> appendPlayIntegrityFix(entry.model)
            is DashboardDetectorCardEntry.Tee -> appendTee(entry.model)
            is DashboardDetectorCardEntry.Su -> appendSu(entry.model)
            is DashboardDetectorCardEntry.SystemProperties -> appendSystemProperties(entry.model)
            is DashboardDetectorCardEntry.Virtualization -> appendVirtualization(entry.model)
            is DashboardDetectorCardEntry.Zygisk -> appendZygisk(entry.model)
        }
    }

    private fun StringBuilder.appendCardHeader(title: String, verdict: String, statusLabel: String) {
        appendLine()
        appendLine("  [$statusLabel] $title")
        appendLine("  Verdict: $verdict")
    }

    private fun StringBuilder.appendHeaderFacts(facts: List<Pair<String, String>>) {
        if (facts.isEmpty()) return
        appendLine("  Header facts:")
        facts.forEach { (label, value) ->
            appendLine("    $label: $value")
        }
    }

    private fun StringBuilder.appendDetailRows(
        sectionTitle: String,
        rows: List<Triple<String, String, String?>>,
    ) {
        if (rows.isEmpty()) return
        appendLine("  $sectionTitle:")
        rows.forEach { (label, value, detail) ->
            val line = StringBuilder("    $label: $value")
            if (!detail.isNullOrBlank() && detail != value) {
                line.append(" ($detail)")
            }
            appendLine(line.toString())
        }
    }

    private fun StringBuilder.appendImpactItems(
        items: List<String>,
    ) {
        if (items.isEmpty()) return
        items.forEach { text ->
            appendLine("    • $text")
        }
    }

    private fun severityLabel(severity: DetectionSeverity): String = when (severity) {
        DetectionSeverity.DANGER -> "DANGER"
        DetectionSeverity.WARNING -> "WARNING"
        DetectionSeverity.INFO -> "INFO"
        DetectionSeverity.ALL_CLEAR -> "CLEAR"
    }

    private fun headerFactsToPairs(facts: List<*>): List<Pair<String, String>> {
        return try {
            @Suppress("UNCHECKED_CAST")
            facts.map { fact ->
                val label = fact!!::class.java.getDeclaredField("label").apply { isAccessible = true }.get(fact) as String
                val value = fact!!::class.java.getDeclaredField("value").apply { isAccessible = true }.get(fact) as String
                label to value
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun detailRowsToTriples(rows: List<*>): List<Triple<String, String, String?>> {
        return try {
            @Suppress("UNCHECKED_CAST")
            rows.map { row ->
                val label = row!!::class.java.getDeclaredField("label").apply { isAccessible = true }.get(row) as String
                val value = row!!::class.java.getDeclaredField("value").apply { isAccessible = true }.get(row) as String
                val detail = try {
                    row::class.java.getDeclaredField("detail").apply { isAccessible = true }.get(row) as? String
                } catch (_: Exception) {
                    null
                }
                Triple(label, value, detail)
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun impactItemsToStrings(items: List<*>): List<String> {
        return try {
            @Suppress("UNCHECKED_CAST")
            items.map { item ->
                item!!::class.java.getDeclaredField("text").apply { isAccessible = true }.get(item) as String
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun StringBuilder.appendBootloader(model: BootloaderCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("State", detailRowsToTriples(model.stateRows))
        appendDetailRows("Attestation", detailRowsToTriples(model.attestationRows))
        appendDetailRows("Properties", detailRowsToTriples(model.propertyRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendMount(model: MountCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Artifacts", detailRowsToTriples(model.artifactRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Filesystem", detailRowsToTriples(model.filesystemRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendCustomRom(model: CustomRomCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Build", detailRowsToTriples(model.buildRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Framework", detailRowsToTriples(model.frameworkRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendSelinux(model: SelinuxCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("State", detailRowsToTriples(model.stateRows))
        appendDetailRows("Policy", detailRowsToTriples(model.policyRows))
        appendDetailRows("Audit", detailRowsToTriples(model.auditRows))
        appendDetailRows("Device", detailRowsToTriples(model.deviceRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
        if (model.policyNotes.isNotEmpty()) {
            appendLine("  Policy notes:")
            appendImpactItems(impactItemsToStrings(model.policyNotes))
        }
        if (model.auditNotes.isNotEmpty()) {
            appendLine("  Audit notes:")
            appendImpactItems(impactItemsToStrings(model.auditNotes))
        }
        if (model.references.isNotEmpty()) {
            appendLine("  References:")
            model.references.forEach { ref ->
                appendLine("    • $ref")
            }
        }
    }

    private fun StringBuilder.appendDangerousApps(model: DangerousAppsCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        if (model.hmaAlert != null) {
            appendLine("  HMA Alert: ${model.hmaAlert.title}")
            appendLine("    ${model.hmaAlert.summary}")
            if (model.hmaAlert.hiddenPackages.isNotEmpty()) {
                appendLine("    Hidden packages:")
                model.hmaAlert.hiddenPackages.forEach { pkg ->
                    appendLine("      ${pkg.appName} (${pkg.packageName}) methods: ${pkg.methods.joinToString()}")
                }
            }
        }
        if (model.packageItems.isNotEmpty()) {
            appendLine("  Packages:")
            model.packageItems.forEach { pkg ->
                appendLine("    ${pkg.appName} (${pkg.packageName}) methods: ${pkg.methods.joinToString()}")
            }
        }
        if (model.context.isNotEmpty()) {
            appendLine("  Context:")
            model.context.forEach { ctx ->
                appendLine("    ${ctx.label}: ${ctx.value}")
            }
        }
        if (model.targetApps.isNotEmpty()) {
            appendLine("  Target apps:")
            model.targetApps.forEach { app ->
                appendLine("    ${app.appName} (${app.packageName}) [${app.category}]")
            }
        }
    }

    private fun StringBuilder.appendKernelCheck(model: KernelCheckCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Identity", detailRowsToTriples(model.identityRows))
        appendDetailRows("Anomalies", detailRowsToTriples(model.anomalyRows))
        appendDetailRows("Behavior", detailRowsToTriples(model.behaviorRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendMemory(model: MemoryCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Hooks", detailRowsToTriples(model.hookRows))
        appendDetailRows("Mapping", detailRowsToTriples(model.mappingRows))
        appendDetailRows("Loader", detailRowsToTriples(model.loaderRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendLSPosed(model: LSPosedCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Binder", detailRowsToTriples(model.binderRows))
        appendDetailRows("Package", detailRowsToTriples(model.packageRows))
        appendDetailRows("Native", detailRowsToTriples(model.nativeRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendNativeRoot(model: NativeRootCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Native", detailRowsToTriples(model.nativeRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Kernel", detailRowsToTriples(model.kernelRows))
        appendDetailRows("Properties", detailRowsToTriples(model.propertyRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendPlayIntegrityFix(model: PlayIntegrityFixCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Properties", detailRowsToTriples(model.propertyRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Native", detailRowsToTriples(model.nativeRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendTee(model: TeeCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        if (model.highlightSignals.isNotEmpty()) {
            appendLine("  Highlight signals:")
            model.highlightSignals.forEach { signal ->
                appendLine("    ${signal.label}: ${signal.value}")
            }
        }
        model.factGroups.forEach { group ->
            appendLine("  ${group.title}:")
            group.rows.forEach { row ->
                appendLine("    ${row.label}: ${row.value}")
            }
        }
        appendLine("  Network: ${model.networkState.summary}")
        appendLine("  Certificate count: ${model.certificateSummary.count}")
        if (model.exportText.isNotBlank()) {
            appendLine()
            appendLine("  --- TEE detailed export ---")
            appendLine(model.exportText)
        }
    }

    private fun StringBuilder.appendSu(model: SuCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Artifacts", detailRowsToTriples(model.artifactRows))
        appendDetailRows("Context", detailRowsToTriples(model.contextRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendSystemProperties(model: SystemPropertiesCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Core", detailRowsToTriples(model.coreRows))
        appendDetailRows("Boot", detailRowsToTriples(model.bootRows))
        appendDetailRows("Build", detailRowsToTriples(model.buildRows))
        appendDetailRows("Source", detailRowsToTriples(model.sourceRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Info", detailRowsToTriples(model.infoRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendVirtualization(model: VirtualizationCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Environment", detailRowsToTriples(model.environmentRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Honeypot", detailRowsToTriples(model.honeypotRows))
        appendDetailRows("Host apps", detailRowsToTriples(model.hostAppRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
        if (model.references.isNotEmpty()) {
            appendLine("  References:")
            model.references.forEach { ref ->
                appendLine("    • $ref")
            }
        }
    }

    private fun StringBuilder.appendZygisk(model: ZygiskCardModel) {
        appendCardHeader(model.title, model.verdict, severityLabel(model.status.severity))
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("State", detailRowsToTriples(model.stateRows))
        appendDetailRows("Signals", detailRowsToTriples(model.signalRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        if (model.impactItems.isNotEmpty()) {
            appendLine("  Impact:")
            appendImpactItems(impactItemsToStrings(model.impactItems))
        }
        if (model.references.isNotEmpty()) {
            appendLine("  References:")
            model.references.forEach { ref ->
                appendLine("    • $ref")
            }
        }
    }

    private fun StringBuilder.appendDeviceInfo(model: DeviceInfoCardModel) {
        appendLine("  ${model.title}")
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        model.sections.forEach { section ->
            appendLine("  ${section.title}:")
            section.rows.forEach { row ->
                appendLine("    ${row.label}: ${row.value}")
            }
        }
    }
}
