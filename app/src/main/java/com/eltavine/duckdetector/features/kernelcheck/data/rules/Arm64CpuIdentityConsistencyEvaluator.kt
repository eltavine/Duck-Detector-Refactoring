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

package com.eltavine.duckdetector.features.kernelcheck.data.rules

import com.eltavine.duckdetector.features.kernelcheck.data.native.Arm64CpuIdentityObservation
import com.eltavine.duckdetector.features.kernelcheck.data.native.Arm64CpuIdentityProbeStatus
import com.eltavine.duckdetector.features.kernelcheck.data.native.CachedCpuIdentitySource
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFinding
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckFindingSeverity
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodOutcome
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckMethodResult
import com.eltavine.duckdetector.features.kernelcheck.domain.KernelCheckReport

data class Arm64CpuIdentityAssessment(
    val finding: KernelCheckFinding?,
    val method: KernelCheckMethodResult,
)

class Arm64CpuIdentityConsistencyEvaluator {

    fun evaluate(
        status: Arm64CpuIdentityProbeStatus,
        observations: List<Arm64CpuIdentityObservation>,
    ): Arm64CpuIdentityAssessment {
        val comparable = observations.filter { observation ->
            observation.affinitySucceeded &&
                    observation.cachedMidr != null &&
                    observation.mrsMidr != null
        }
        val mismatches = comparable.filter { observation ->
            normalizeMidr(observation.cachedMidr!!, observation.cachedSource) !=
                    normalizeMidr(observation.mrsMidr!!, observation.cachedSource)
        }
        val detail = observations.joinToString(separator = "\n", transform = ::formatObservation)
        val hasCompleteCoverage = status == Arm64CpuIdentityProbeStatus.COMPLETED &&
                observations.isNotEmpty() &&
                comparable.size == observations.size

        val finding = mismatches.takeIf { it.isNotEmpty() }?.let {
            KernelCheckFinding(
                id = KernelCheckReport.CPU_IDENTITY_MISMATCH_FINDING_ID,
                label = "ARM64 CPU identity",
                value = "${it.size} core mismatch(es)",
                detail = detail,
                severity = KernelCheckFindingSeverity.HARD,
            )
        }

        val method = when {
            finding != null -> KernelCheckMethodResult(
                label = METHOD_LABEL,
                summary = finding.value,
                outcome = KernelCheckMethodOutcome.DETECTED,
                detail = detail,
            )

            hasCompleteCoverage -> KernelCheckMethodResult(
                label = METHOD_LABEL,
                summary = "${comparable.size} CPU(s) agree",
                outcome = KernelCheckMethodOutcome.CLEAN,
                detail = detail,
            )

            comparable.isNotEmpty() -> supportMethod(
                summary = "Partial (${comparable.size}/${observations.size} CPUs)",
                detail = detail,
            )

            status == Arm64CpuIdentityProbeStatus.UNSUPPORTED_ABI -> supportMethod(
                summary = "Unsupported ABI",
                detail = "Pinned MIDR_EL1 comparison is available only on ARM64.",
            )

            status == Arm64CpuIdentityProbeStatus.AFFINITY_UNAVAILABLE -> supportMethod(
                summary = "Affinity unavailable",
                detail = "The current thread's CPU affinity could not be read, so a same-CPU comparison was not safe.",
            )

            // A kernel without the MRS emulation can never answer this, which is a different state
            // from a read that was attempted and failed.
            status == Arm64CpuIdentityProbeStatus.CPUID_EMULATION_UNAVAILABLE -> supportMethod(
                summary = "CPUID emulation unavailable",
                detail = buildString {
                    append(
                        "The kernel does not advertise HWCAP_CPUID, so EL0 has no MRS emulation " +
                            "for MIDR_EL1 and no register value exists to compare against the " +
                            "cached identity.",
                    )
                    if (detail.isNotBlank()) {
                        append('\n')
                        append(detail)
                    }
                },
            )

            else -> supportMethod(
                summary = "Unavailable",
                detail = detail.ifBlank {
                    "No logical CPU yielded both a cached MIDR and a safely emulated MIDR_EL1 read."
                },
            )
        }

        return Arm64CpuIdentityAssessment(finding = finding, method = method)
    }

    internal fun normalizeMidr(
        midr: Long,
        cachedSource: CachedCpuIdentitySource,
    ): Long {
        return if (cachedSource == CachedCpuIdentitySource.PROC_CPUINFO) {
            midr and PROC_IDENTITY_FIELD_MASK
        } else {
            midr and UINT32_MASK
        }
    }

    private fun formatObservation(observation: Arm64CpuIdentityObservation): String {
        val state = when {
            !observation.affinitySucceeded -> "affinity failed"
            observation.cachedMidr == null -> "cached MIDR unavailable"
            observation.mrsMidr == null -> "MRS MIDR_EL1 unavailable"
            normalizeMidr(observation.cachedMidr, observation.cachedSource) ==
                    normalizeMidr(observation.mrsMidr, observation.cachedSource) -> "consistent"
            else -> "mismatch"
        }
        return buildString {
            append("CPU ")
            append(observation.cpu)
            append(": cached=")
            append(observation.cachedMidr.formatMidr())
            append(" (")
            append(observation.cachedSource.label)
            append("), mrs=")
            append(observation.mrsMidr.formatMidr())
            append(", ")
            append(state)
        }
    }

    private fun supportMethod(
        summary: String,
        detail: String,
    ): KernelCheckMethodResult {
        return KernelCheckMethodResult(
            label = METHOD_LABEL,
            summary = summary,
            outcome = KernelCheckMethodOutcome.SUPPORT,
            detail = detail,
        )
    }

    private fun Long?.formatMidr(): String {
        return this?.let { "0x${it.toString(radix = 16).padStart(8, '0')}" } ?: "N/A"
    }

    private val CachedCpuIdentitySource.label: String
        get() = when (this) {
            CachedCpuIdentitySource.SYSFS -> "sysfs"
            CachedCpuIdentitySource.PROC_CPUINFO -> "/proc/cpuinfo"
            CachedCpuIdentitySource.NONE -> "none"
        }

    private companion object {
        const val METHOD_LABEL = "arm64CpuIdentity"

        // Architecture[19:16] is omitted because /proc/cpuinfo reports a fixed architecture value.
        const val PROC_IDENTITY_FIELD_MASK = 0xfff0_ffffL
        const val UINT32_MASK = 0xffff_ffffL
    }
}
