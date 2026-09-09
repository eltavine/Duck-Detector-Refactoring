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
        appendBanner(state)
        appendExecutiveSummary(state)
        appendTopFindings(state)
        appendDetectorCards(state)
        appendDeviceInfo(state.deviceInfoCard)
        appendFooter()
    }

    private fun StringBuilder.appendBanner(state: DashboardUiState) {
        val deviceInfo = state.deviceInfoCard
        val brand = deviceInfo.headerFacts.firstOrNull { it.label.equals("brand", true) }?.value
        val model = deviceInfo.headerFacts.firstOrNull { it.label.equals("model", true) }?.value
        val android = deviceInfo.headerFacts.firstOrNull { it.label.equals("android", true) }?.value
        val sdk = deviceInfo.headerFacts.firstOrNull { it.label.equals("sdk", true) }?.value

        appendLine("================================================================================")
        appendLine("                      DUCK DETECTOR — SECURITY SCAN REPORT                      ")
        appendLine("================================================================================")
        if (!brand.isNullOrBlank() && !model.isNullOrBlank()) {
            val osStr = if (!android.isNullOrBlank()) " (Android $android, API ${sdk ?: "unknown"})" else ""
            appendLine("  Target Device  : $brand $model$osStr")
        }
        appendLine("  App Version    : ${BuildConfig.VERSION_NAME} (Build ${BuildConfig.VERSION_CODE})")
        appendLine("  Build Commit   : ${BuildConfig.BUILD_HASH}")
        appendLine("  Build Time     : ${formatBuildTimeUtc(BuildConfig.BUILD_TIME_UTC)} (UTC)")
        appendLine("  Report Time    : ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss (z)", Locale.US).format(Date())}")
        appendLine()
    }

    private fun StringBuilder.appendExecutiveSummary(state: DashboardUiState) {
        appendLine("--------------------------------------------------------------------------------")
        appendLine("  EXECUTIVE SUMMARY")
        appendLine("--------------------------------------------------------------------------------")
        val badge = severityBadge(state.overview.status.severity)
        appendLine("  Overall Status : $badge ${state.overview.headline}")
        appendLine("  Summary        : ${state.overview.summary}")
        appendLine()
        appendLine("  Scan Statistics:")
        state.overview.metrics.forEach { metric ->
            val icon = when (metric.label.lowercase()) {
                "danger" -> "[✖]"
                "warning" -> "[▲]"
                "ready" -> "[✔]"
                else -> "[·]"
            }
            appendLine("    $icon ${metric.label.padEnd(9)}: ${metric.value}")
        }
        appendLine()
    }

    private fun StringBuilder.appendTopFindings(state: DashboardUiState) {
        appendLine("--------------------------------------------------------------------------------")
        appendLine("  TOP FINDINGS")
        appendLine("--------------------------------------------------------------------------------")
        if (state.topFindings.isEmpty()) {
            appendLine("  (No security threats or warnings detected)")
        } else {
            state.topFindings.forEach { finding ->
                val badge = severityBadge(finding.status.severity)
                appendLine("  $badge ${finding.detectorTitle}")
                appendLine("    Headline : ${finding.headline}")
                if (finding.detail.isNotBlank() && finding.detail != finding.headline) {
                    appendLine("    Details  :")
                    finding.detail.trim().lines().map { it.trimEnd() }.filter { it.isNotBlank() }.forEach { line ->
                        appendLine("      $line")
                    }
                }
                appendLine()
            }
        }
    }

    private fun StringBuilder.appendDetectorCards(state: DashboardUiState) {
        state.detectorCards.forEach { entry ->
            appendDetectorCard(entry)
        }
        appendLine()
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

    private fun StringBuilder.appendCardHeader(title: String, verdict: String, severity: DetectionSeverity) {
        appendLine()
        appendLine("--------------------------------------------------------------------------------")
        val badge = severityBadge(severity)
        appendLine("  $badge $title")
        appendLine("  Verdict      : $verdict")
    }

    private fun StringBuilder.appendHeaderFacts(facts: List<Pair<String, String>>) {
        if (facts.isEmpty()) return
        val formatted = facts.joinToString("  |  ") { "${it.first}: ${it.second}" }
        appendLine("  Quick Facts  : $formatted")
    }

    private fun StringBuilder.appendDetailRows(
        sectionTitle: String,
        rows: List<Triple<String, String, String?>>,
    ) {
        if (rows.isEmpty()) return
        appendLine()
        appendLine("  [$sectionTitle]")
        rows.forEach { (label, value, detail) ->
            formatDetailRow(label, value, detail)
        }
    }

    private fun StringBuilder.formatDetailRow(label: String, value: String, detail: String?) {
        val trimmedValue = value.trim()
        val hasValue = trimmedValue.isNotBlank()
        val trimmedDetail = detail?.trim()
        val hasDetail = !trimmedDetail.isNullOrBlank() && trimmedDetail != trimmedValue

        if (!hasValue && !hasDetail) {
            appendLine("    • $label")
            return
        }

        if (!hasValue && hasDetail) {
            appendLine("    • $label")
            formatDetailContent(trimmedDetail)
            return
        }

        if (!hasDetail) {
            appendLine("    • $label: $trimmedValue")
            return
        }

        val detailLines = trimmedDetail.lines().map { it.trimEnd() }.filter { it.isNotBlank() }
        if (detailLines.size == 1 && detailLines[0].length <= 60 && !detailLines[0].contains(" = ") && !detailLines[0].contains(" | ")) {
            appendLine("    • $label: $trimmedValue (${detailLines[0]})")
        } else {
            appendLine("    • $label: $trimmedValue")
            detailLines.forEach { line ->
                appendLine("        $line")
            }
        }
    }

    private fun StringBuilder.formatDetailContent(detail: String) {
        detail.lines().map { it.trimEnd() }.filter { it.isNotBlank() }.forEach { line ->
            appendLine("        $line")
        }
    }

    private fun StringBuilder.appendImpactItems(
        sectionTitle: String = "Impact & Guidance",
        items: List<String>,
    ) {
        if (items.isEmpty()) return
        appendLine()
        appendLine("  [$sectionTitle]")
        items.forEach { text ->
            val lines = text.trim().lines().map { it.trimEnd() }.filter { it.isNotBlank() }
            if (lines.isNotEmpty()) {
                appendLine("    • ${lines.first()}")
                lines.drop(1).forEach { line ->
                    appendLine("      $line")
                }
            }
        }
    }

    private fun severityBadge(severity: DetectionSeverity): String = when (severity) {
        DetectionSeverity.DANGER -> "[✖ DANGER]"
        DetectionSeverity.WARNING -> "[▲ WARNING]"
        DetectionSeverity.INFO -> "[ℹ INFO]"
        DetectionSeverity.ALL_CLEAR -> "[✔ CLEAR]"
    }

    private fun headerFactsToPairs(facts: List<*>): List<Pair<String, String>> {
        return try {
            @Suppress("UNCHECKED_CAST")
            facts.map { fact ->
                val item = requireNotNull(fact)
                val label = item::class.java.getDeclaredField("label").apply { isAccessible = true }.get(item) as String
                val value = item::class.java.getDeclaredField("value").apply { isAccessible = true }.get(item) as String
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
                val item = requireNotNull(row)
                val label = item::class.java.getDeclaredField("label").apply { isAccessible = true }.get(item) as String
                val value = item::class.java.getDeclaredField("value").apply { isAccessible = true }.get(item) as String
                val detail = try {
                    item::class.java.getDeclaredField("detail").apply { isAccessible = true }.get(item) as? String
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
                val nonNullItem = requireNotNull(item)
                nonNullItem::class.java.getDeclaredField("text").apply { isAccessible = true }.get(nonNullItem) as String
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun StringBuilder.appendBootloader(model: BootloaderCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("State", detailRowsToTriples(model.stateRows))
        appendDetailRows("Attestation", detailRowsToTriples(model.attestationRows))
        appendDetailRows("Properties", detailRowsToTriples(model.propertyRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendMount(model: MountCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Artifacts", detailRowsToTriples(model.artifactRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Filesystem", detailRowsToTriples(model.filesystemRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendCustomRom(model: CustomRomCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Build", detailRowsToTriples(model.buildRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Framework", detailRowsToTriples(model.frameworkRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendSelinux(model: SelinuxCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("State", detailRowsToTriples(model.stateRows))
        appendDetailRows("Policy", detailRowsToTriples(model.policyRows))
        appendDetailRows("Audit", detailRowsToTriples(model.auditRows))
        appendDetailRows("Device", detailRowsToTriples(model.deviceRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
        if (model.policyNotes.isNotEmpty()) {
            appendImpactItems("Policy Notes", impactItemsToStrings(model.policyNotes))
        }
        if (model.auditNotes.isNotEmpty()) {
            appendImpactItems("Audit Notes", impactItemsToStrings(model.auditNotes))
        }
        if (model.references.isNotEmpty()) {
            appendLine()
            appendLine("  [References]")
            model.references.forEach { ref ->
                appendLine("    • $ref")
            }
        }
    }

    private fun StringBuilder.appendDangerousApps(model: DangerousAppsCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        if (model.hmaAlert != null) {
            appendLine()
            appendLine("  [HMA Alert: ${model.hmaAlert.title}]")
            appendLine("    Summary: ${model.hmaAlert.summary}")
            if (model.hmaAlert.hiddenPackages.isNotEmpty()) {
                appendLine("    Hidden Packages:")
                model.hmaAlert.hiddenPackages.forEach { pkg ->
                    appendLine("      • ${pkg.appName} (${pkg.packageName}) [methods: ${pkg.methods.joinToString()}]")
                }
            }
        }
        if (model.packageItems.isNotEmpty()) {
            appendLine()
            appendLine("  [Detected Packages]")
            model.packageItems.forEach { pkg ->
                appendLine("    • ${pkg.appName} (${pkg.packageName}) [methods: ${pkg.methods.joinToString()}]")
            }
        }
        if (model.context.isNotEmpty()) {
            appendLine()
            appendLine("  [Context & Inventory]")
            model.context.forEach { ctx ->
                appendLine("    • ${ctx.label}: ${ctx.value}")
            }
        }
        if (model.targetApps.isNotEmpty()) {
            appendLine()
            val byCategory = model.targetApps.groupBy { it.category }
            appendLine("  [Monitored Package Catalog (${model.targetApps.size} targets across ${byCategory.size} categories)]")
            byCategory.forEach { (category, apps) ->
                appendLine("    • $category (${apps.size}):")
                formatWrappedList("        ", apps.map { "${it.appName} (${it.packageName})" })
            }
        }
    }

    private fun StringBuilder.formatWrappedList(indent: String, items: List<String>) {
        var currentLine = StringBuilder(indent)
        items.forEachIndexed { index, item ->
            val suffix = if (index < items.lastIndex) ", " else ""
            if (currentLine.length + item.length + suffix.length > 95 && currentLine.trim().isNotEmpty()) {
                appendLine(currentLine.toString())
                currentLine = StringBuilder(indent).append(item).append(suffix)
            } else {
                currentLine.append(item).append(suffix)
            }
        }
        if (currentLine.trim().isNotEmpty()) {
            appendLine(currentLine.toString())
        }
    }

    private fun StringBuilder.appendKernelCheck(model: KernelCheckCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Identity", detailRowsToTriples(model.identityRows))
        appendDetailRows("Anomalies", detailRowsToTriples(model.anomalyRows))
        appendDetailRows("Behavior", detailRowsToTriples(model.behaviorRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendMemory(model: MemoryCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Hooks", detailRowsToTriples(model.hookRows))
        appendDetailRows("Mapping", detailRowsToTriples(model.mappingRows))
        appendDetailRows("Loader", detailRowsToTriples(model.loaderRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendLSPosed(model: LSPosedCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Binder", detailRowsToTriples(model.binderRows))
        appendDetailRows("Package", detailRowsToTriples(model.packageRows))
        appendDetailRows("SELinux policy", detailRowsToTriples(model.policyRows))
        appendDetailRows("Native", detailRowsToTriples(model.nativeRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendNativeRoot(model: NativeRootCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Native", detailRowsToTriples(model.nativeRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Kernel", detailRowsToTriples(model.kernelRows))
        appendDetailRows("Properties", detailRowsToTriples(model.propertyRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendPlayIntegrityFix(model: PlayIntegrityFixCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Properties", detailRowsToTriples(model.propertyRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Native", detailRowsToTriples(model.nativeRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendTee(model: TeeCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        if (model.highlightSignals.isNotEmpty()) {
            appendLine()
            appendLine("  [Highlight Signals]")
            model.highlightSignals.forEach { signal ->
                appendLine("    • ${signal.label}: ${signal.value}")
            }
        }
        model.factGroups.forEach { group ->
            appendLine()
            appendLine("  [${group.title}]")
            group.rows.forEach { row ->
                val lines = row.value.trim().lines().map { it.trimEnd() }.filter { it.isNotBlank() }
                if (lines.size <= 1) {
                    appendLine("    • ${row.label}: ${row.value.trim()}")
                } else {
                    appendLine("    • ${row.label}:")
                    lines.forEach { l ->
                        appendLine("        $l")
                    }
                }
            }
        }
        appendLine()
        appendLine("  [Environment & Network]")
        appendLine("    • Network Status    : ${model.networkState.summary}")
        appendLine("    • Certificate Count : ${model.certificateSummary.count}")
        model.certificateSummary.certificates.forEachIndexed { index, certificate ->
            appendLine("    • Certificate ${index + 1}       : ${certificate.slotLabel}")
            appendLine("        Subject           : ${certificate.subject}")
            appendLine("        Issuer            : ${certificate.issuer}")
            appendLine("        Serial Number     : ${certificate.serialNumber}")
            appendLine("        Validity          : ${certificate.validFrom} to ${certificate.validUntil}")
            appendLine("        Signature          : ${certificate.signatureAlgorithm}")
            appendLine("        Public Key        : ${certificate.publicKeySummary}")
        }
        if (model.exportText.isNotBlank()) {
            appendLine()
            appendLine("  [TEE Detailed Export]")
            model.exportText.trimEnd().lines().forEach { line ->
                appendLine("    $line")
            }
        }
    }

    private fun StringBuilder.appendSu(model: SuCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Artifacts", detailRowsToTriples(model.artifactRows))
        appendDetailRows("Context", detailRowsToTriples(model.contextRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendSystemProperties(model: SystemPropertiesCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
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
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
    }

    private fun StringBuilder.appendVirtualization(model: VirtualizationCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("Environment", detailRowsToTriples(model.environmentRows))
        appendDetailRows("Runtime", detailRowsToTriples(model.runtimeRows))
        appendDetailRows("Consistency", detailRowsToTriples(model.consistencyRows))
        appendDetailRows("Honeypot", detailRowsToTriples(model.honeypotRows))
        appendDetailRows("Host apps", detailRowsToTriples(model.hostAppRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        appendDetailRows("Scan", detailRowsToTriples(model.scanRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
        if (model.references.isNotEmpty()) {
            appendLine()
            appendLine("  [References]")
            model.references.forEach { ref ->
                appendLine("    • $ref")
            }
        }
    }

    private fun StringBuilder.appendZygisk(model: ZygiskCardModel) {
        appendCardHeader(model.title, model.verdict, model.status.severity)
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        appendDetailRows("State", detailRowsToTriples(model.stateRows))
        appendDetailRows("Signals", detailRowsToTriples(model.signalRows))
        appendDetailRows("Methods", detailRowsToTriples(model.methodRows))
        if (model.impactItems.isNotEmpty()) {
            appendImpactItems("Impact & Guidance", impactItemsToStrings(model.impactItems))
        }
        if (model.references.isNotEmpty()) {
            appendLine()
            appendLine("  [References]")
            model.references.forEach { ref ->
                appendLine("    • $ref")
            }
        }
    }

    private fun StringBuilder.appendDeviceInfo(model: DeviceInfoCardModel) {
        appendLine()
        appendLine("================================================================================")
        appendLine("  DEVICE & SYSTEM SPECIFICATIONS")
        appendLine("================================================================================")
        appendHeaderFacts(headerFactsToPairs(model.headerFacts))
        model.sections.forEach { section ->
            appendLine()
            appendLine("  [${section.title}]")
            val maxLabelLen = section.rows.maxOfOrNull { it.label.length } ?: 16
            val padLen = (maxLabelLen + 2).coerceIn(16, 28)
            section.rows.forEach { row ->
                val paddedLabel = row.label.padEnd(padLen)
                appendLine("    • $paddedLabel: ${row.value}")
            }
        }
    }

    private fun StringBuilder.appendFooter() {
        appendLine()
        appendLine("================================================================================")
        appendLine("                                 END OF REPORT                                  ")
        appendLine("================================================================================")
    }
}
