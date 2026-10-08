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
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootStage
import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingVerdict
import com.eltavine.duckdetector.features.nativeroot.domain.hasReducedCoverage
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootImpactItemModel

internal fun buildImpactItems(report: NativeRootReport): List<NativeRootImpactItemModel> {
    return when (report.stage) {
        NativeRootStage.LOADING -> listOf(
            NativeRootImpactItemModel(
                text = "Gathering local native root evidence.",
                status = DetectorStatus.info(InfoKind.SUPPORT),
            ),
        )

        NativeRootStage.FAILED -> listOf(
            NativeRootImpactItemModel(
                text = report.errorMessage ?: "Native Root scan failed.",
                status = DetectorStatus.info(InfoKind.ERROR),
            ),
        )

        NativeRootStage.READY -> buildList {
            if (report.hasDangerFindings) {
                add(
                    NativeRootImpactItemModel(
                        text = "Direct native hits are stronger than plain package or property signals because they come from syscall behavior, runtime processes, cgroup visibility mismatches, or corroborated runtime residue paths.",
                        status = DetectorStatus.danger(),
                    ),
                )
            } else if (report.hasFindingWarnings) {
                add(
                    NativeRootImpactItemModel(
                        text = "Isolated-process mount drift, manager manifest fingerprints, kernel strings, property residue, or cgroup leakage can indicate native-root history or selective runtime hiding, but they are weaker than direct syscall-side probes.",
                        status = DetectorStatus.warning(),
                    ),
                )
            } else if (report.srcuTiming.analysis.verdict == SrcuTimingVerdict.REPEATABLE_DELAY) {
                add(NativeRootImpactItemModel(
                    text = "The optional timing experiment found a repeatable delay relative to both controls. Background fsnotify readers and scheduling remain possible causes; this does not identify a root solution.",
                    status = DetectorStatus.warning(),
                ))
            } else if (report.nativeAvailable) {
                add(
                    if (report.hasReducedCoverage()) {
                        NativeRootImpactItemModel(
                            text = "No native root indicator surfaced from available probes, but one or more support-only evidence paths were unavailable or scoped.",
                            status = DetectorStatus.info(InfoKind.SUPPORT),
                        )
                    } else {
                        NativeRootImpactItemModel(
                            text = "No common KernelSU, APatch, Magisk, SUSFS, or cgroup-leak traces surfaced from the current probe set.",
                            status = DetectorStatus.allClear(),
                        )
                    },
                )
            }
            add(
                NativeRootImpactItemModel(
                    text = if (report.nativeAvailable) {
                        if (report.hasReducedCoverage()) {
                            "Reduced coverage lowers confidence without implying a positive root detection."
                        } else {
                            "A determined root can still hide or remove residue, so absence of native hits is not proof of a stock device."
                        }
                    } else {
                        "Native coverage was unavailable, so this card should not be treated as a strong clean verdict."
                    },
                    status = DetectorStatus.info(InfoKind.SUPPORT),
                ),
            )
        }
    }
}
