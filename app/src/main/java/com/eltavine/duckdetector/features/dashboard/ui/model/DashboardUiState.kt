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

package com.eltavine.duckdetector.features.dashboard.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind
import com.eltavine.duckdetector.features.bootloader.ui.model.BootloaderCardModel
import com.eltavine.duckdetector.features.customrom.ui.model.CustomRomCardModel
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.dangerousapps.ui.model.DangerousAppsCardModel
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
import java.util.Locale

data class DashboardOverviewMetricModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class DashboardOverviewModel(
    val title: String,
    val headline: String,
    val summary: String,
    val status: DetectorStatus,
    val metrics: List<DashboardOverviewMetricModel>,
    val showTitleIcon: Boolean = false,
)

data class DashboardFindingModel(
    val detectorTitle: String,
    val headline: String,
    val detail: String,
    val status: DetectorStatus,
)

data class DashboardDetectorContribution(
    val id: String,
    val title: String,
    val status: DetectorStatus,
    val headline: String,
    val summary: String,
    val ready: Boolean,
)

sealed interface DashboardDetectorCardEntry {
    val id: String
    val status: DetectorStatus

    data class Bootloader(
        val model: BootloaderCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "bootloader"
        override val status: DetectorStatus = model.status
    }

    data class Mount(
        val model: MountCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "mount"
        override val status: DetectorStatus = model.status
    }

    data class Memory(
        val model: MemoryCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "memory"
        override val status: DetectorStatus = model.status
    }

    data class LSPosed(
        val model: LSPosedCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "lsposed"
        override val status: DetectorStatus = model.status
    }

    data class Selinux(
        val model: SelinuxCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "selinux"
        override val status: DetectorStatus = model.status
    }

    data class DangerousApps(
        val model: DangerousAppsCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "dangerous_apps"
        override val status: DetectorStatus = model.status
    }

    data class PlayIntegrityFix(
        val model: PlayIntegrityFixCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "play_integrity_fix"
        override val status: DetectorStatus = model.status
    }

    data class NativeRoot(
        val model: NativeRootCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "native_root"
        override val status: DetectorStatus = model.status
    }

    data class Tee(
        val model: TeeCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "tee"
        override val status: DetectorStatus = model.status
    }

    data class Su(
        val model: SuCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "su"
        override val status: DetectorStatus = model.status
    }

    data class CustomRom(
        val model: CustomRomCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "custom_rom"
        override val status: DetectorStatus = model.status
    }

    data class KernelCheck(
        val model: KernelCheckCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "kernel_check"
        override val status: DetectorStatus = model.status
    }

    data class SystemProperties(
        val model: SystemPropertiesCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "system_properties"
        override val status: DetectorStatus = model.status
    }

    data class Zygisk(
        val model: ZygiskCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "zygisk"
        override val status: DetectorStatus = model.status
    }

    data class Virtualization(
        val model: VirtualizationCardModel,
    ) : DashboardDetectorCardEntry {
        override val id: String = "virtualization"
        override val status: DetectorStatus = model.status
    }
}

data class DashboardUiState(
    val overview: DashboardOverviewModel,
    val topFindings: List<DashboardFindingModel>,
    val detectorCards: List<DashboardDetectorCardEntry>,
    val deviceInfoCard: DeviceInfoCardModel,
    val isLoading: Boolean,
)

fun buildDashboardOverview(
    contributions: List<DashboardDetectorContribution>,
    scanDurationMillis: Long? = null,
): DashboardOverviewModel {
    val total = contributions.size
    val readyCount = contributions.count { it.ready }
    val pendingCount = total - readyCount
    val dangerCount = contributions.count { it.status.severity == DetectionSeverity.DANGER }
    val warningCount = contributions.count { it.status.severity == DetectionSeverity.WARNING }
    val infoErrorCount = contributions.count {
        it.status.severity == DetectionSeverity.INFO && it.status.infoKind == InfoKind.ERROR
    }

    val focusTitles = prioritizedContributions(contributions)
        .take(2)
        .map { it.title }

    val overviewStatus = when {
        dangerCount > 0 -> DetectorStatus.danger()
        warningCount > 0 -> DetectorStatus.warning()
        infoErrorCount > 0 -> DetectorStatus.info(InfoKind.ERROR)
        readyCount == 0 -> DetectorStatus.info(InfoKind.SUPPORT)
        pendingCount > 0 -> DetectorStatus.info(InfoKind.SUPPORT)
        else -> DetectorStatus.allClear()
    }

    val headline = when {
        dangerCount > 0 -> "Danger"
        warningCount > 0 -> "Warning"
        infoErrorCount > 0 -> "Info"
        readyCount == 0 -> "Ready"
        pendingCount > 0 -> "Pending"
        else -> "OK"
    }

    val summary = when {
        dangerCount > 0 -> "Start with ${focusTitles.joinToString(separator = " and ")}."
        warningCount > 0 -> "Review ${focusTitles.joinToString(separator = " and ")} next."
        infoErrorCount > 0 -> "${focusTitles.joinToString(separator = " and ")} need more context before treating results as clean."
        readyCount == 0 -> "Detector cards will populate as local checks complete."
        pendingCount > 0 -> "Additional modules are still collecting their local evidence."
        else -> "Use the detector cards below to inspect local evidence in detail."
    }

    return DashboardOverviewModel(
        title = if (scanDurationMillis != null && pendingCount == 0) {
            "Scan time ${formatScanDuration(scanDurationMillis)}"
        } else {
            "Security overview"
        },
        headline = headline,
        summary = summary,
        status = overviewStatus,
        metrics = listOf(
            DashboardOverviewMetricModel(
                label = "Danger",
                value = dangerCount.toString(),
                status = if (dangerCount > 0) DetectorStatus.danger() else DetectorStatus.allClear(),
            ),
            DashboardOverviewMetricModel(
                label = "Warning",
                value = warningCount.toString(),
                status = if (warningCount > 0) DetectorStatus.warning() else DetectorStatus.allClear(),
            ),
            DashboardOverviewMetricModel(
                label = "Ready",
                value = readyCount.toString(),
                status = if (readyCount > 0) DetectorStatus.allClear() else DetectorStatus.info(
                    InfoKind.SUPPORT
                ),
            ),
            DashboardOverviewMetricModel(
                label = "Pending",
                value = pendingCount.toString(),
                status = if (pendingCount > 0) DetectorStatus.info(InfoKind.SUPPORT) else DetectorStatus.allClear(),
            ),
        ),
        showTitleIcon = scanDurationMillis != null && pendingCount == 0,
    )
}

private fun formatScanDuration(
    durationMillis: Long,
): String {
    return when {
        durationMillis < 1_000L -> "${durationMillis}ms"
        durationMillis < 10_000L -> String.format(Locale.US, "%.1fs", durationMillis / 1_000f)
        else -> "${(durationMillis + 500L) / 1_000L}s"
    }
}

fun buildDashboardFindings(
    contributions: List<DashboardDetectorContribution>,
): List<DashboardFindingModel> {
    val prioritized = prioritizedContributions(contributions)
    val attentionFindings = prioritized.filter { contribution ->
        when (contribution.status.severity) {
            DetectionSeverity.DANGER,
            DetectionSeverity.WARNING -> true

            DetectionSeverity.INFO -> contribution.status.infoKind == InfoKind.ERROR
            DetectionSeverity.ALL_CLEAR -> false
        }
    }
    if (attentionFindings.isNotEmpty()) {
        return attentionFindings.take(3).map { contribution ->
            DashboardFindingModel(
                detectorTitle = contribution.title,
                headline = contribution.headline,
                detail = contribution.summary,
                status = contribution.status,
            )
        }
    }

    if (contributions.any { !it.ready }) {
        return listOf(
            DashboardFindingModel(
                detectorTitle = "Scan status",
                headline = "Waiting for detector evidence",
                detail = "Detector cards will expand as modules finish collecting local evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )
    }

    return listOf(
        DashboardFindingModel(
            detectorTitle = "Overview",
            headline = "No urgent findings in ready modules",
            detail = "Open detector cards below to review detailed local evidence and secondary checks.",
            status = DetectorStatus.allClear(),
        ),
    )
}

private fun prioritizedContributions(
    contributions: List<DashboardDetectorContribution>,
): List<DashboardDetectorContribution> {
    return contributions.sortedWith(
        compareBy<DashboardDetectorContribution> { contribution ->
            detectorPriority(contribution.status)
        }.thenBy { if (it.ready) 0 else 1 }
            .thenBy { it.title },
    )
}

fun sortDashboardDetectorCards(
    entries: List<DashboardDetectorCardEntry>,
): List<DashboardDetectorCardEntry> {
    return entries.sortedWith(
        compareBy<DashboardDetectorCardEntry> { entry ->
            detectorPriority(entry.status)
        }.thenBy { entry ->
            when (entry) {
                is DashboardDetectorCardEntry.Bootloader -> entry.model.title
                is DashboardDetectorCardEntry.CustomRom -> entry.model.title
                is DashboardDetectorCardEntry.DangerousApps -> entry.model.title
                is DashboardDetectorCardEntry.KernelCheck -> entry.model.title
                is DashboardDetectorCardEntry.LSPosed -> entry.model.title
                is DashboardDetectorCardEntry.Memory -> entry.model.title
                is DashboardDetectorCardEntry.Mount -> entry.model.title
                is DashboardDetectorCardEntry.NativeRoot -> entry.model.title
                is DashboardDetectorCardEntry.PlayIntegrityFix -> entry.model.title
                is DashboardDetectorCardEntry.Selinux -> entry.model.title
                is DashboardDetectorCardEntry.Su -> entry.model.title
                is DashboardDetectorCardEntry.SystemProperties -> entry.model.title
                is DashboardDetectorCardEntry.Tee -> entry.model.title
                is DashboardDetectorCardEntry.Virtualization -> entry.model.title
                is DashboardDetectorCardEntry.Zygisk -> entry.model.title
            }
        },
    )
}

private fun detectorPriority(
    status: DetectorStatus,
): Int {
    return when (status.severity) {
        DetectionSeverity.DANGER -> 0
        DetectionSeverity.WARNING -> 1
        DetectionSeverity.INFO -> if (status.infoKind == InfoKind.ERROR) 2 else 3
        DetectionSeverity.ALL_CLEAR -> 4
    }
}
