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

package com.eltavine.duckdetector.features.lsposed.data.art

import android.content.Context
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

internal class ArtMethodIntegrityProbe(
    context: Context,
    private val nativeBridge: ArtMethodNativeBridge = ArtMethodNativeBridge(),
    private val probeManager: ArtMethodProbeManager = ArtMethodProbeManager(context),
) {

    suspend fun run(): ArtMethodIntegrityResult {
        val behaviorClean = verifySentinelBehavior()
        val mainSnapshot = nativeBridge.collectSnapshot()
        val isolatedSnapshot = probeManager.collectIsolatedSnapshot()
        val available = mainSnapshot.available && isolatedSnapshot.available

        val signals = buildList {
            if (!behaviorClean) {
                add(
                    artSignal(
                        id = "sentinel_behavior",
                        label = "ART sentinel behavior",
                        value = "Changed",
                        severity = LSPosedSignalSeverity.DANGER,
                        detail = "One or more local sentinel methods returned an unexpected value before entrypoint comparison.",
                    ),
                )
            }
            addAll(buildSuspiciousCandidateSignals(mainSnapshot, isolatedSnapshot))
            if (available) {
                addAll(buildCrossProcessDriftSignals(mainSnapshot, isolatedSnapshot))
            }
        }

        return ArtMethodIntegrityResult(
            available = available,
            mainSnapshot = mainSnapshot,
            isolatedSnapshot = isolatedSnapshot,
            sentinelBehaviorClean = behaviorClean,
            signals = signals,
            detail = buildDetail(mainSnapshot, isolatedSnapshot, behaviorClean),
        )
    }

    private fun verifySentinelBehavior(): Boolean {
        return runCatching {
            ArtMethodSentinel.staticToken(ArtMethodSentinel.STATIC_INPUT) == ArtMethodSentinel.STATIC_EXPECTED &&
                    ArtMethodSentinel.virtualToken(ArtMethodSentinel.VIRTUAL_INPUT) == ArtMethodSentinel.VIRTUAL_EXPECTED &&
                    ArtMethodSentinel.stringToken(ArtMethodSentinel.STRING_INPUT) == ArtMethodSentinel.STRING_EXPECTED
        }.getOrDefault(false)
    }

    private fun buildSuspiciousCandidateSignals(
        mainSnapshot: ArtMethodSnapshot,
        isolatedSnapshot: ArtMethodSnapshot,
    ): List<com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal> {
        val isolatedSuspicious = isolatedSnapshot.methods
            .flatMap { it.candidates }
            .map { it.label to it.normalizedSignature }
            .toSet()

        return mainSnapshot.methods.flatMap { method ->
            method.candidates
                .filter { it.suspicious }
                .filterNot { candidate ->
                    candidate.label to candidate.normalizedSignature in isolatedSuspicious
                }
                .map { candidate ->
                    artSignal(
                        id = "candidate_${candidate.label}_${candidate.offset}",
                        label = "ART entrypoint",
                        value = candidate.regionKind,
                        severity = LSPosedSignalSeverity.DANGER,
                        detail = buildString {
                            append(candidate.label)
                            append(" ArtMethod+")
                            append(candidate.offset)
                            append(" points to a suspicious executable region in the main process.")
                            appendLine()
                            append(candidate.detail)
                            appendLine()
                            append(candidate.path.ifBlank { "<anonymous executable mapping>" })
                        },
                    )
                }
        }
    }

    private fun buildCrossProcessDriftSignals(
        mainSnapshot: ArtMethodSnapshot,
        isolatedSnapshot: ArtMethodSnapshot,
    ): List<com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal> {
        val isolatedByLabel = isolatedSnapshot.methods.associateBy { it.label }
        return mainSnapshot.methods.mapNotNull { mainMethod ->
            val isolatedMethod = isolatedByLabel[mainMethod.label] ?: return@mapNotNull null
            val mainPrimary = mainMethod.primaryCandidate ?: return@mapNotNull null
            val isolatedPrimary = isolatedMethod.primaryCandidate ?: return@mapNotNull null
            if (mainPrimary.sameBenignFamily(isolatedPrimary)) {
                return@mapNotNull null
            }
            if (mainPrimary.isJitLike() || isolatedPrimary.isJitLike()) {
                return@mapNotNull null
            }

            artSignal(
                id = "drift_${mainMethod.label}",
                label = "ART entrypoint drift",
                value = "${mainPrimary.regionKind} vs ${isolatedPrimary.regionKind}",
                severity = LSPosedSignalSeverity.WARNING,
                detail = buildString {
                    append("Primary executable candidate differs between the app process and the isolated process.")
                    appendLine()
                    append("main: ")
                    append(mainPrimary.detail)
                    appendLine()
                    append(mainPrimary.path.ifBlank { "<anonymous>" })
                    appendLine()
                    append("isolated: ")
                    append(isolatedPrimary.detail)
                    appendLine()
                    append(isolatedPrimary.path.ifBlank { "<anonymous>" })
                },
            )
        }
    }

    private fun ArtMethodCandidate.sameBenignFamily(other: ArtMethodCandidate): Boolean {
        if (regionKind == other.regionKind && normalizedSignature == other.normalizedSignature) {
            return true
        }
        val benign = setOf("ART_RUNTIME", "BOOT_IMAGE", "APP_OAT")
        return regionKind in benign && other.regionKind in benign
    }

    private fun ArtMethodCandidate.isJitLike(): Boolean {
        return regionKind == "JIT_CACHE" || path.contains("jit", ignoreCase = true)
    }

    private fun buildDetail(
        mainSnapshot: ArtMethodSnapshot,
        isolatedSnapshot: ArtMethodSnapshot,
        behaviorClean: Boolean,
    ): String {
        return buildString {
            append("Sentinel behavior: ")
            append(if (behaviorClean) "clean" else "changed")
            appendLine()
            append("Main process: ")
            append(mainSnapshot.methodCount)
            append(" method(s), ")
            append(mainSnapshot.candidateCount)
            append(" executable candidate(s), ")
            append(mainSnapshot.suspiciousCandidateCount)
            append(" suspicious.")
            appendLine()
            append("Isolated process: ")
            append(isolatedSnapshot.methodCount)
            append(" method(s), ")
            append(isolatedSnapshot.candidateCount)
            append(" executable candidate(s), ")
            append(isolatedSnapshot.suspiciousCandidateCount)
            append(" suspicious.")
        }
    }
}
