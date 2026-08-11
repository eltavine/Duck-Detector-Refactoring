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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import com.eltavine.duckdetector.features.virtualization.data.service.VirtualizationIsolatedProbeManager

/**
 * Cross-process mount view divergence probe, ported from the PrivIsolated project.
 *
 * An Android isolated helper process (VirtualizationIsolatedProbeService) enumerates the
 * /proc/<pid>/mountinfo view of every process it can see and reports how many distinct mount
 * tables exist. Root solutions that hide mounts selectively (Magisk DenyList, KernelSU umount)
 * make different processes expose different tables, so the distinct view count drifts away from
 * the expected baseline. Direct root tokens (magisk / KSU / /adb/) in any visible mount table are
 * reported as a stronger finding.
 */
data class ProcMountViewDivergenceProbeResult(
    val available: Boolean,
    val isolatedProcessAvailable: Boolean,
    val distinctViewCount: Int,
    val expectedViewCount: Int,
    val scannedPidCount: Int,
    val divergent: Boolean,
    val tokenHit: Boolean,
    val tokenHitDetail: String,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val signalCount: Int
        get() = findings.count { it.severity != NativeRootFindingSeverity.INFO }
}

class ProcMountViewDivergenceProbe(
    context: Context? = null,
    private val isolatedProbeManager: VirtualizationIsolatedProbeManager =
        VirtualizationIsolatedProbeManager(context?.applicationContext),
) {

    suspend fun run(): ProcMountViewDivergenceProbeResult {
        val isolatedSnapshot = isolatedProbeManager.collect()
        return evaluate(isolatedSnapshot)
    }

    internal fun evaluate(
        isolatedSnapshot: VirtualizationRemoteSnapshot,
    ): ProcMountViewDivergenceProbeResult {
        if (!isolatedSnapshot.available) {
            return ProcMountViewDivergenceProbeResult(
                available = false,
                isolatedProcessAvailable = false,
                distinctViewCount = 0,
                expectedViewCount = 1,
                scannedPidCount = 0,
                divergent = false,
                tokenHit = false,
                tokenHitDetail = "",
                findings = emptyList(),
                detail = isolatedSnapshot.errorDetail.ifBlank {
                    "The isolated helper process did not return mount view data."
                },
            )
        }

        if (
            isolatedSnapshot.profile != VirtualizationRemoteProfile.ISOLATED ||
            !isolatedSnapshot.procMountViewAvailable
        ) {
            return ProcMountViewDivergenceProbeResult(
                available = true,
                isolatedProcessAvailable = false,
                distinctViewCount = isolatedSnapshot.procMountViewCount,
                expectedViewCount = isolatedSnapshot.procMountViewExpected,
                scannedPidCount = isolatedSnapshot.procMountViewPidCount,
                divergent = false,
                tokenHit = false,
                tokenHitDetail = "",
                findings = emptyList(),
                detail = isolatedSnapshot.procMountViewDetail.ifBlank {
                    "The isolated helper process did not expose a cross-process mount view scan."
                },
            )
        }

        val divergent = isolatedSnapshot.procMountViewDivergent
        val tokenHit = isolatedSnapshot.procMountViewTokenHit

        val findings = buildList {
            if (tokenHit) {
                add(
                    NativeRootFinding(
                        id = "proc_mount_view_token",
                        label = "Root mount token in process view",
                        value = "Detected",
                        detail = isolatedSnapshot.procMountViewTokenDetail.ifBlank {
                            "A visible /proc/<pid>/mountinfo table contains a root-managed mount source."
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.DANGER,
                        detailMonospace = true,
                    ),
                )
            }
            if (divergent) {
                add(
                    NativeRootFinding(
                        id = "proc_mount_view_divergence",
                        label = "Hidden mount view divergence",
                        value = "${isolatedSnapshot.procMountViewCount} view(s)",
                        detail = buildString {
                            append("Cross-process mountinfo diverges from the isolated baseline. ")
                            append(isolatedSnapshot.procMountViewCount)
                            append(" distinct table(s) vs expected ")
                            append(isolatedSnapshot.procMountViewExpected)
                            append(" across ")
                            append(isolatedSnapshot.procMountViewPidCount)
                            append(" process(es).")
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    ),
                )
            }
        }

        return ProcMountViewDivergenceProbeResult(
            available = true,
            isolatedProcessAvailable = true,
            distinctViewCount = isolatedSnapshot.procMountViewCount,
            expectedViewCount = isolatedSnapshot.procMountViewExpected,
            scannedPidCount = isolatedSnapshot.procMountViewPidCount,
            divergent = divergent,
            tokenHit = tokenHit,
            tokenHitDetail = isolatedSnapshot.procMountViewTokenDetail,
            findings = findings,
            detail = buildString {
                append("Compared cross-process mount tables through an isolated helper process. ")
                append(isolatedSnapshot.procMountViewDetail)
                if (tokenHit) {
                    append("\nDirect root token: ")
                    append(isolatedSnapshot.procMountViewTokenDetail)
                }
            },
        )
    }
}
