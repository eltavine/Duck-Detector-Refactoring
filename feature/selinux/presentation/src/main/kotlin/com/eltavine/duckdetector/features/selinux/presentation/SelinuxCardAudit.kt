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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditNoteKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxDetailRowModel
import com.eltavine.duckdetector.features.selinux.presentation.model.SelinuxImpactItemModel

internal fun buildAuditRows(analysis: SelinuxAuditIntegrityAnalysis?): List<SelinuxDetailRowModel> {
    if (analysis == null) {
        return emptyList()
    }

    val rows = mutableListOf(
        SelinuxDetailRowModel(
            label = "Surface",
            value = auditIntegrityLabel(analysis),
            status = auditIntegrityStatus(analysis),
        ),
        SelinuxDetailRowModel(
            label = "Runtime markers",
            value = when {
                analysis.runtimeHits.isNotEmpty() -> "${analysis.runtimeHits.size} hit(s)"
                analysis.logcatChecked -> "Not observed"
                else -> "Unavailable"
            },
            status = when {
                analysis.runtimeHits.isNotEmpty() -> DetectorStatus.danger()
                analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = when {
                analysis.runtimeHits.isNotEmpty() ->
                    "Known auditpatch runtime markers surfaced in recent auditd event logs."

                analysis.logcatChecked ->
                    "Recent auditd event logs were readable, but absence of markers is not proof of a clean audit surface."

                else ->
                    "The current app could not read recent auditd event logs."
            },
        ),
        SelinuxDetailRowModel(
            label = "AVC side-channel",
            value = when {
                analysis.sideChannelHits.isNotEmpty() -> "${analysis.sideChannelHits.size} hit(s)"
                analysis.logcatChecked -> "Not observed"
                else -> "Unavailable"
            },
            status = when {
                analysis.sideChannelHits.isNotEmpty() -> DetectorStatus.warning()
                analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = when {
                analysis.sideChannelHits.isNotEmpty() ->
                    "Readable auditd event logs exposed the same nonce-tagged controlled AVC denial seen by the direct libselinux callback probe."

                analysis.directProbeUsed && analysis.logcatChecked ->
                    "No matching nonce-tagged controlled AVC denial surfaced in the readable auditd event window."

                analysis.logcatChecked ->
                    "No matching controlled AVC denial surfaced in the readable auditd event window, but absence is not proof."

                else ->
                    "The current app could not read recent auditd event logs."
            },
        ),
        SelinuxDetailRowModel(
            label = "su-related AVC",
            value = when {
                analysis.suspiciousActorHits.isNotEmpty() -> "${analysis.suspiciousActorHits.size} hit(s)"
                analysis.logcatChecked -> "Not observed"
                else -> "Unavailable"
            },
            status = when {
                analysis.suspiciousActorHits.isNotEmpty() -> DetectorStatus.warning()
                analysis.logcatChecked -> DetectorStatus.info(InfoKind.SUPPORT)
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = when {
                analysis.suspiciousActorHits.isNotEmpty() ->
                    "Readable AVC denials referenced a root-related process name (comm) or executable (exe). Access to /data/adb alone is not a root-process signal."

                analysis.logcatChecked ->
                    "No su-related actor string surfaced in the readable canonical AVC window."

                else ->
                    "The current app could not read recent auditd event logs."
            },
        ),
        SelinuxDetailRowModel(
            label = "Residue paths",
            value = when {
                analysis.residueHits.isNotEmpty() -> "${analysis.residueHits.size} hit(s)"
                analysis.residueObservable -> "None"
                else -> "Not observable"
            },
            status = when {
                analysis.residueHits.any { it.strongSignal } -> DetectorStatus.warning()
                analysis.residueHits.isNotEmpty() -> DetectorStatus.info(InfoKind.SUPPORT)
                analysis.residueObservable -> DetectorStatus.allClear()
                else -> DetectorStatus.info(InfoKind.SUPPORT)
            },
            detail = when {
                analysis.residueHits.isNotEmpty() -> "Readable module residue matched common ZN-AuditPatch locations."
                analysis.residueObservable -> "No auditpatch residue exists under common module paths."
                else -> "Common module paths sit under /data/adb, which this app cannot search, so residue there is not visible."
            },
        ),
    )

    analysis.runtimeHits.forEach { hit ->
        rows += SelinuxDetailRowModel(
            label = hit.label,
            value = hit.value,
            status = if (hit.strongSignal) DetectorStatus.danger() else DetectorStatus.warning(),
            detail = hit.detail,
        )
    }
    analysis.sideChannelHits.forEach { hit ->
        rows += SelinuxDetailRowModel(
            label = hit.label,
            value = hit.value,
            status = DetectorStatus.warning(),
            detail = hit.detail,
        )
    }
    analysis.suspiciousActorHits.forEach { hit ->
        rows += SelinuxDetailRowModel(
            label = hit.label,
            value = hit.value,
            status = DetectorStatus.warning(),
            detail = hit.detail,
        )
    }
    analysis.residueHits.forEach { hit ->
        rows += SelinuxDetailRowModel(
            label = hit.label,
            value = "Readable",
            status = if (hit.strongSignal) DetectorStatus.warning() else DetectorStatus.info(
                InfoKind.SUPPORT
            ),
            detail = listOfNotNull(hit.value, hit.detail).joinToString(" | "),
        )
    }
    return rows
}

internal fun buildAuditNotes(analysis: SelinuxAuditIntegrityAnalysis?): List<SelinuxImpactItemModel> {
    return analysis?.notes?.map { note ->
        SelinuxImpactItemModel(text = note.text, status = note.kind.status())
    }.orEmpty()
}

private fun SelinuxAuditNoteKind.status(): DetectorStatus = when (this) {
    SelinuxAuditNoteKind.SIDE_CHANNEL_LEAK,
    SelinuxAuditNoteKind.SU_ACTOR_REFERENCED,
    SelinuxAuditNoteKind.RESIDUE_FOUND -> DetectorStatus.warning()

    SelinuxAuditNoteKind.DIRECT_PROBE_NOT_LEAKED -> DetectorStatus.allClear()

    // Keeps the status a keyword match gave this note; see "SELinux note statuses" in the follow-ups.
    SelinuxAuditNoteKind.PROBES_EXPOSED_TAMPERING -> DetectorStatus.info(InfoKind.SUPPORT)

    SelinuxAuditNoteKind.EVENT_BUFFER_CLEAN,
    SelinuxAuditNoteKind.EVENTS_NOT_GUARANTEED,
    SelinuxAuditNoteKind.EVENT_LOGS_UNAVAILABLE,
    SelinuxAuditNoteKind.NO_RESIDUE,
    SelinuxAuditNoteKind.RESIDUE_UNCHECKED,
    SelinuxAuditNoteKind.ABSENCE_NOT_PROOF -> DetectorStatus.info(InfoKind.SUPPORT)
}

internal fun auditIntegrityLabel(analysis: SelinuxAuditIntegrityAnalysis?): String {
    return when (analysis?.state) {
        SelinuxAuditIntegrityState.CLEAR -> "No signal"
        SelinuxAuditIntegrityState.RESIDUE -> "Residue"
        SelinuxAuditIntegrityState.EXPOSED -> "Exposed"
        SelinuxAuditIntegrityState.TAMPERED -> "Tampered"
        SelinuxAuditIntegrityState.INCONCLUSIVE -> "Inconclusive"
        null -> "Skipped"
    }
}

internal fun auditIntegrityStatus(analysis: SelinuxAuditIntegrityAnalysis?): DetectorStatus {
    return when (analysis?.state) {
        SelinuxAuditIntegrityState.CLEAR -> DetectorStatus.allClear()
        SelinuxAuditIntegrityState.RESIDUE -> DetectorStatus.warning()
        SelinuxAuditIntegrityState.EXPOSED -> DetectorStatus.warning()
        SelinuxAuditIntegrityState.TAMPERED -> DetectorStatus.danger()
        SelinuxAuditIntegrityState.INCONCLUSIVE -> DetectorStatus.info(InfoKind.SUPPORT)
        null -> DetectorStatus.info(InfoKind.SUPPORT)
    }
}

internal fun buildDeviceRows(report: SelinuxReport): List<SelinuxDetailRowModel> {
    return listOf(
        SelinuxDetailRowModel(
            label = "Android",
            value = if (report.androidVersion.isNotBlank()) report.androidVersion else "Unknown",
            status = DetectorStatus.info(InfoKind.SUPPORT),
        ),
        SelinuxDetailRowModel(
            label = "API level",
            value = if (report.apiLevel > 0) report.apiLevel.toString() else "Unknown",
            status = DetectorStatus.info(InfoKind.SUPPORT),
        ),
        SelinuxDetailRowModel(
            label = "Required since",
            value = "Android 5.0 (API 21)",
            status = DetectorStatus.info(InfoKind.SUPPORT),
        ),
    )
}

internal fun buildReferences(): List<String> {
    return listOf(
        "SELinux paradox: permission denied can prove enforcing mode.",
        "Enforcing mode blocks disallowed actions instead of only logging them.",
        "Production Android devices are expected to run enforcing SELinux.",
        "app_zygote can query SELinux context validity through selinux_check_context, which ultimately writes to /sys/fs/selinux/context.",
        "A dedicated app_zygote carrier can also probe privileged context materialization by writing candidate labels to /proc/self/attr/current and classifying non-EINVAL outcomes.",
        "The policyload/access seqno oracle must be captured inside zygotePreloadName; the isolated child may lose app_zygote SELinuxfs access and should downgrade missing coverage to info.",
        "Audit or log surfaces can be rewritten in user space, so missing suspicious tcontext values is not always proof.",
        "Readable AVC denial lines should be treated as audit-surface leakage, not as direct proof of a root process.",
        "comm, exe, path, and name fields inside AVC logs are supporting hints, not standalone proof of a live su daemon.",
    )
}
