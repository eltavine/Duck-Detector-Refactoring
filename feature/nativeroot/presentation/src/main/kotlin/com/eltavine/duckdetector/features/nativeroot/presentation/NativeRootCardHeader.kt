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

package com.eltavine.duckdetector.features.nativeroot.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingVerdict
import com.eltavine.duckdetector.features.nativeroot.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.nativeroot.domain.hasRuntimeReducedCoverage
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootHeaderFact
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootHeaderFactModel

// Warnings from real findings, without the opt-in experiment's own warning-level signal. Established
// findings outrank the experimental timing signal in the headline, summary and impact.
internal val NativeRootReport.hasFindingWarnings: Boolean
    get() = findings.any { it.severity == NativeRootFindingSeverity.WARNING }

internal fun buildSubtitle(report: NativeRootReport): String {
    return when (report.stage) {
        NativeRootStage.LOADING -> "supercall + prctl + setresuid + runtime paths + /proc + isolated mount"
        NativeRootStage.FAILED -> "native root scan failed"
        NativeRootStage.READY -> when {
            !report.nativeAvailable && report.findings.isEmpty() -> "native detector unavailable"
            else -> "${report.pathCheckCount} paths · ${report.processCheckedCount} proc entries · ${report.cgroupPathCheckCount} cgroup dirs · ${report.kernelSourceCount} kernel sources · ${report.propertyCheckCount} props"
        }
    }
}

internal fun buildVerdict(report: NativeRootReport): String {
    return when (report.stage) {
        NativeRootStage.LOADING -> "Scanning kernel-root indicators"
        NativeRootStage.FAILED -> "Native Root scan failed"
        NativeRootStage.READY -> when {
            report.tempRootCveExploitDetected -> "CVE-2026-43499 temp root tooling found"
            report.tempRootDetected -> "Temp root artifacts detected in /data/local/tmp"
            report.kernelSuDetected && report.aPatchDetected -> "KernelSU and APatch indicators detected"
            report.selfSuDomain -> "Current app already runs in KernelSU su domain"
            report.kernelSuDetected && report.ksuSupercallProbeHit -> "KernelSU detected via ksu_driver"
            report.kernelSuDetected && report.prctlProbeHit -> "KernelSU detected via prctl"
            report.kernelSuDetected -> "KernelSU indicators detected"
            report.aPatchDetected -> "APatch indicators detected"
            report.magiskDetected -> "Magisk native indicators detected"
            report.rootDetected -> "Root indicators detected"
            report.hasDangerFindings -> "${report.dangerFindingCount} runtime root signal(s)"
            report.mountAnchorDriftCount > 0 -> "Isolated mount drift suggests namespace tampering"
            report.mountDriftSignalCount > 0 -> "Isolated-process namespace drift needs review"
            report.ksuThroneHuntDetected -> "KernelSU throne hunt traversal observed"
            report.ksuManagerPackagePresent && report.ksuManagerTraitHitCount > 0 ->
                "KernelSU manager weak fingerprint detected"

            report.ksuManagerPackagePresent -> "KernelSU manager package detected"
            report.hasFindingWarnings -> "${report.warningFindingCount} native signal(s) need review"
            report.srcuTiming.analysis.verdict == SrcuTimingVerdict.REPEATABLE_DELAY -> "Experimental fsnotify/SRCU timing anomaly"
            !report.nativeAvailable -> "Native detector unavailable"
            report.hasReducedCoverage() -> "Native root scan has reduced coverage"
            else -> "No native root indicators"
        }
    }
}

internal fun buildSummary(report: NativeRootReport): String {
    val base = when (report.stage) {
        NativeRootStage.LOADING ->
            "Native probes are collecting read-only supercall, syscall, side-channel, self-process, isolated-process mount drift, manager manifest, path, cgroup, kernel-string, and property evidence."

        NativeRootStage.FAILED ->
            report.errorMessage ?: "Native Root scan failed before evidence could be assembled."

        NativeRootStage.READY -> when {
            report.hasDangerFindings ->
                "Read-only ksu_driver hits, direct syscall hits, self-process IOC, root-manager paths, curated runtime residue paths, /data/local/tmp metadata drift, cgroup/process leakage, unexpected root processes, or isolated-process namespace drift indicate active native root infrastructure."

            report.hasFindingWarnings ->
                "Only weaker isolated-process mount drift, cross-process mount view divergence, manager manifest fingerprints, process, cgroup, kernel, property, or metadata residue surfaced. These are review-worthy, but not as strong as direct native probes."

            report.srcuTiming.analysis.verdict == SrcuTimingVerdict.REPEATABLE_DELAY ->
                "The optional experiment observed a repeatable fsnotify/SRCU timing delay relative to both controls. This is supporting contention evidence; it does not identify a root solution. Other indicators retain their own meaning."

            !report.nativeAvailable ->
                "This detector relies mostly on JNI-backed native probes. Native coverage was unavailable on this build, and the remaining runtime checks stayed clean."

            report.hasReducedCoverage() ->
                "No native root indicator surfaced from available probes, but one or more direct, cgroup, isolated-process, or package-visibility evidence paths had reduced coverage."

            else ->
                "KernelSU read-only supercall, prctl-side probes, KernelPatch side channel, self-process IOC, isolated-process mount drift and cross-process mount view comparison, manager manifest fingerprint, SUSFS side-channel, /data/adb artifacts, curated tmp/system/storage residue paths, /data/local/tmp metadata, root-process audit, cgroup/process leakage, kernel strings, and properties stayed clean."
        }
    }
    if (report.stage != NativeRootStage.READY) {
        return base
    }
    return when {
        report.ksuSupercallBlocked ->
            "$base The read-only ksu_driver probe was blocked by app seccomp on this device, so the verdict falls back to prctl, self-process IOC, path, cgroup, kernel-string, and property evidence."

        !report.ksuSupercallAttempted ->
            "$base The read-only ksu_driver probe was unavailable, so this card relied on the remaining native checks."

        else -> base
    }
}

internal fun buildHeaderFacts(report: NativeRootReport): List<NativeRootHeaderFactModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> placeholderFacts(
            "Pending",
            DetectorStatus.info(InfoKind.SUPPORT)
        )

        NativeRootStage.FAILED -> placeholderFacts("Error", DetectorStatus.info(InfoKind.ERROR))
        NativeRootStage.READY -> listOf(
            NativeRootHeaderFactModel(
                fact = NativeRootHeaderFact.FLAGS,
                value = familyValue(report),
                status = when {
                    report.detectedFamilies.isEmpty() && report.hasReducedCoverage() -> DetectorStatus.info(
                        InfoKind.SUPPORT
                    )
                    report.detectedFamilies.isEmpty() && report.nativeAvailable -> DetectorStatus.allClear()
                    report.detectedFamilies.isEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
                    else -> DetectorStatus.danger()
                },
            ),
            NativeRootHeaderFactModel(
                fact = NativeRootHeaderFact.DIRECT,
                value = when {
                    report.directFindings.isNotEmpty() -> report.directFindings.size.toString()
                    report.ksuSupercallBlocked || !report.ksuSupercallAttempted -> "Limited"
                    else -> "Clean"
                },
                status = when {
                    report.directFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                    report.directFindings.isNotEmpty() -> DetectorStatus.warning()
                    report.ksuSupercallBlocked || !report.ksuSupercallAttempted -> DetectorStatus.info(
                        InfoKind.SUPPORT
                    )
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootHeaderFactModel(
                fact = NativeRootHeaderFact.KERNEL,
                value = when {
                    report.kernelFindings.isNotEmpty() -> report.kernelFindings.size.toString()
                    report.nativeAvailable -> "Clean"
                    else -> "N/A"
                },
                status = when {
                    report.kernelFindings.isNotEmpty() -> DetectorStatus.warning()
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
            NativeRootHeaderFactModel(
                fact = NativeRootHeaderFact.RUNTIME,
                value = if (report.runtimeFindings.isEmpty()) {
                    when {
                        !report.nativeAvailable -> "N/A"
                        report.hasRuntimeReducedCoverage() -> "Limited"
                        report.nativeAvailable -> "Clean"
                        else -> "N/A"
                    }
                } else {
                    report.runtimeFindings.size.toString()
                },
                status = when {
                    report.runtimeFindings.any { it.severity == NativeRootFindingSeverity.DANGER } -> DetectorStatus.danger()
                    report.runtimeFindings.isNotEmpty() -> DetectorStatus.warning()
                    !report.nativeAvailable -> DetectorStatus.info(InfoKind.SUPPORT)
                    report.hasRuntimeReducedCoverage() -> DetectorStatus.info(InfoKind.SUPPORT)
                    report.nativeAvailable -> DetectorStatus.allClear()
                    else -> DetectorStatus.info(InfoKind.SUPPORT)
                },
            ),
        )
    }
}

private fun placeholderFacts(
    value: String,
    status: DetectorStatus,
): List<NativeRootHeaderFactModel> {
    return listOf(
        NativeRootHeaderFactModel(NativeRootHeaderFact.FLAGS, value, status),
        NativeRootHeaderFactModel(NativeRootHeaderFact.DIRECT, value, status),
        NativeRootHeaderFactModel(NativeRootHeaderFact.KERNEL, value, status),
        NativeRootHeaderFactModel(NativeRootHeaderFact.RUNTIME, value, status),
    )
}

private fun familyValue(report: NativeRootReport): String {
    return when {
        report.detectedFamilies.isEmpty() && report.nativeAvailable -> "None"
        report.detectedFamilies.isEmpty() -> "N/A"
        report.detectedFamilies.size <= 2 -> report.detectedFamilies.joinToString("/")
        else -> report.detectedFamilies.take(2)
            .joinToString("/") + " +${report.detectedFamilies.size - 2}"
    }
}
