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

package com.eltavine.duckdetector.features.bootloader.data.repository

import com.eltavine.duckdetector.capability.attestation.data.BootConsistencyResult
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.bootloader.data.widevine.WidevineBootloaderEvidence
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFinding
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity

internal fun buildConsistencyFindings(
    bootConsistency: BootConsistencyResult,
    sourceSignals: List<SystemPropertySignal>,
    consistencySignals: List<SystemPropertySignal>,
    widevineEvidence: WidevineBootloaderEvidence,
): List<BootloaderFinding> {
    val findings = mutableListOf<BootloaderFinding>()

    if (bootConsistency.vbmetaDigestMismatch) {
        findings += BootloaderFinding(
            id = "vbmeta_digest_mismatch",
            label = "Attested hash vs vbmeta digest",
            value = "Mismatch",
            group = BootloaderFindingGroup.CONSISTENCY,
            severity = BootloaderFindingSeverity.DANGER,
            detail = bootConsistency.detail,
        )
    }
    if (bootConsistency.vbmetaDigestMissingWhileAttestedHashPresent) {
        findings += BootloaderFinding(
            id = "vbmeta_digest_missing",
            label = "Attested hash vs vbmeta digest",
            value = "Digest missing",
            group = BootloaderFindingGroup.CONSISTENCY,
            severity = BootloaderFindingSeverity.DANGER,
            detail = bootConsistency.detail,
        )
    }
    if (bootConsistency.verifiedBootHashAllZeros) {
        findings += BootloaderFinding(
            id = "boot_hash_all_zero",
            label = "Attested boot hash",
            value = "All zeros",
            group = BootloaderFindingGroup.CONSISTENCY,
            severity = BootloaderFindingSeverity.DANGER,
            detail = bootConsistency.detail,
        )
    }
    if (bootConsistency.verifiedBootKeyAllZeros) {
        findings += BootloaderFinding(
            id = "boot_key_all_zero",
            label = "Attested boot key",
            value = "All zeros",
            group = BootloaderFindingGroup.CONSISTENCY,
            severity = BootloaderFindingSeverity.DANGER,
            detail = bootConsistency.detail,
        )
    }
    if (!bootConsistency.hasHardAnomaly) {
        findings += BootloaderFinding(
            id = "boot_consistency_clean",
            label = "Attested hash vs vbmeta digest",
            value = when {
                bootConsistency.runtimeComparisonPerformed -> "Aligned"
                else -> "Not compared"
            },
            group = BootloaderFindingGroup.CONSISTENCY,
            severity = if (bootConsistency.runtimeComparisonPerformed) {
                BootloaderFindingSeverity.SAFE
            } else {
                BootloaderFindingSeverity.INFO
            },
            detail = bootConsistency.detail,
        )
    }

    sourceSignals.forEach { signal ->
        findings += systemSignalFinding(
            signal = signal,
            group = BootloaderFindingGroup.CONSISTENCY,
        )
    }
    consistencySignals.forEach { signal ->
        findings += systemSignalFinding(
            signal = signal,
            group = BootloaderFindingGroup.CONSISTENCY,
        )
    }
    findings += widevineEvidence.findings

    return findings
}

private fun systemSignalFinding(
    signal: SystemPropertySignal,
    group: BootloaderFindingGroup,
): BootloaderFinding {
    return BootloaderFinding(
        id = "signal_${signal.property}_${signal.value}",
        label = signal.property,
        value = signal.value,
        group = group,
        severity = when (signal.severity) {
            SystemPropertySeverity.SAFE -> BootloaderFindingSeverity.SAFE
            SystemPropertySeverity.WARNING -> BootloaderFindingSeverity.WARNING
            SystemPropertySeverity.DANGER -> BootloaderFindingSeverity.DANGER
            SystemPropertySeverity.NEUTRAL -> BootloaderFindingSeverity.INFO
        },
        detail = buildString {
            append(signal.description)
            appendLine()
            append("Source: ${sourceLabel(signal.source)}")
            signal.detail?.takeIf { it.isNotBlank() }?.let {
                appendLine()
                append(it)
            }
        },
        detailMonospace = true,
    )
}
