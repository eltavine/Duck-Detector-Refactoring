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

package com.eltavine.duckdetector.features.lsposed.data.probes

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import com.eltavine.duckdetector.features.selinux.data.native.SelinuxContextValiditySnapshot

data class LSPosedDirtyPolicyProbeResult(
    val available: Boolean,
    val probeAttempted: Boolean,
    val carrierContext: String?,
    val carrierMatchesExpected: Boolean,
    val controlsPassed: Boolean,
    val stable: Boolean,
    val queryMethod: String,
    val accessControlAllowed: Boolean?,
    val negativeControlRejected: Boolean?,
    val systemServerExecmemAllowed: Boolean?,
    val magiskBinderCallAllowed: Boolean?,
    val ksuFileReadAllowed: Boolean?,
    val lsposedFileReadAllowed: Boolean?,
    val failureReason: String?,
    val notes: List<String>,
    val signals: List<LSPosedSignal>,
) {
    val hitCount: Int
        get() = signals.size

    val summary: String
        get() = when {
            available && lsposedFileReadAllowed == true -> "LSPosed rule present"
            !available -> "Unavailable"
            hitCount > 0 -> "$hitCount dirty rule(s)"
            else -> "Clean"
        }

    val outcome: LSPosedMethodOutcome
        get() = when {
            available && lsposedFileReadAllowed == true -> LSPosedMethodOutcome.DETECTED
            !available -> LSPosedMethodOutcome.SUPPORT
            signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
            signals.any { it.severity == LSPosedSignalSeverity.WARNING } -> LSPosedMethodOutcome.WARNING
            else -> LSPosedMethodOutcome.CLEAN
        }

    val detail: String
        get() = buildString {
            append("Runs DirtySepolicy-style access queries through the existing app_zygote SELinux carrier. ")
            append("The LSPosed-specific rule is untrusted_app -> lsposed_file:file read.")
            appendLine()
            append("Carrier=").append(carrierContext ?: "<unreadable>")
            append(" | carrier match=").append(if (carrierMatchesExpected) "yes" else "no")
            append(" | controls=").append(if (controlsPassed) "passed" else "failed")
            append(" | repeatability=").append(if (stable) "stable" else "unstable")
            append(" | query=").append(queryMethod)
            appendLine()
            append("access control=").append(ruleLabel(accessControlAllowed))
            append(" | negative control rejected=").append(yesNoLabel(negativeControlRejected))
            append(" | system_server execmem=").append(ruleLabel(systemServerExecmemAllowed))
            append(" | Magisk binder=").append(ruleLabel(magiskBinderCallAllowed))
            append(" | KernelSU file read=").append(ruleLabel(ksuFileReadAllowed))
            append(" | LSPosed file read=").append(ruleLabel(lsposedFileReadAllowed))
            failureReason?.takeIf { it.isNotBlank() }?.let {
                appendLine()
                append(it)
            }
            notes.take(4).forEach { note ->
                appendLine()
                append(note)
            }
        }

    private fun ruleLabel(value: Boolean?): String {
        return when (value) {
            true -> "allowed"
            false -> "denied"
            null -> "unknown"
        }
    }

    private fun yesNoLabel(value: Boolean?): String {
        return when (value) {
            true -> "yes"
            false -> "no"
            null -> "unknown"
        }
    }
}

class LSPosedDirtyPolicyProbe {
    fun run(snapshot: SelinuxContextValiditySnapshot): LSPosedDirtyPolicyProbeResult {
        val available = snapshot.dirtyPolicyAvailable &&
            snapshot.dirtyPolicyProbeAttempted &&
            snapshot.dirtyPolicyCarrierMatchesExpected &&
            snapshot.dirtyPolicyControlsPassed &&
            snapshot.dirtyPolicyStable &&
            snapshot.dirtyPolicyAccessControlAllowed == true &&
            snapshot.dirtyPolicyNegativeControlRejected == true

        return LSPosedDirtyPolicyProbeResult(
            available = available,
            probeAttempted = snapshot.dirtyPolicyProbeAttempted,
            carrierContext = snapshot.dirtyPolicyCarrierContext,
            carrierMatchesExpected = snapshot.dirtyPolicyCarrierMatchesExpected,
            controlsPassed = snapshot.dirtyPolicyControlsPassed,
            stable = snapshot.dirtyPolicyStable,
            queryMethod = snapshot.dirtyPolicyQueryMethod.ifBlank {
                "android.os.SELinux.checkSELinuxAccess"
            },
            accessControlAllowed = snapshot.dirtyPolicyAccessControlAllowed,
            negativeControlRejected = snapshot.dirtyPolicyNegativeControlRejected,
            systemServerExecmemAllowed = snapshot.dirtyPolicySystemServerExecmemAllowed,
            magiskBinderCallAllowed = snapshot.dirtyPolicyMagiskBinderCallAllowed,
            ksuFileReadAllowed = snapshot.dirtyPolicyKsuFileReadAllowed,
            lsposedFileReadAllowed = snapshot.dirtyPolicyLsposedFileReadAllowed,
            failureReason = snapshot.dirtyPolicyFailureReason,
            notes = snapshot.dirtyPolicyNotes,
            signals = if (available) buildSignals(snapshot) else emptyList(),
        )
    }

    private fun buildSignals(
        snapshot: SelinuxContextValiditySnapshot,
    ): List<LSPosedSignal> {
        return buildList {
            if (snapshot.dirtyPolicySystemServerExecmemAllowed == true) {
                add(
                    policySignal(
                        id = "policy_system_server_execmem",
                        label = "system_server execmem",
                        value = "Allowed",
                        severity = LSPosedSignalSeverity.WARNING,
                        detail = "The app_zygote SELinux access oracle reported system_server -> system_server:process execmem as allowed.",
                    ),
                )
            }
            if (snapshot.dirtyPolicyMagiskBinderCallAllowed == true) {
                add(
                    policySignal(
                        id = "policy_magisk_binder_call",
                        label = "Magisk binder",
                        value = "Allowed",
                        severity = LSPosedSignalSeverity.WARNING,
                        detail = "The app_zygote SELinux access oracle reported untrusted_app -> magisk:binder call as allowed. This is supporting dirty-policy evidence, not an LSPosed-specific rule.",
                    ),
                )
            }
            if (snapshot.dirtyPolicyKsuFileReadAllowed == true) {
                add(
                    policySignal(
                        id = "policy_ksu_file_read",
                        label = "KernelSU file read",
                        value = "Allowed",
                        severity = LSPosedSignalSeverity.WARNING,
                        detail = "The app_zygote SELinux access oracle reported untrusted_app -> ksu_file:file read as allowed. This is supporting dirty-policy evidence, not an LSPosed-specific rule.",
                    ),
                )
            }
            if (snapshot.dirtyPolicyLsposedFileReadAllowed == true) {
                add(
                    policySignal(
                        id = "policy_lsposed_file_read",
                        label = "LSPosed file read",
                        value = "Allowed",
                        severity = LSPosedSignalSeverity.DANGER,
                        detail = "The app_zygote SELinux access oracle reported untrusted_app -> lsposed_file:file read as allowed.",
                    ),
                )
            }
        }
    }

    private fun policySignal(
        id: String,
        label: String,
        value: String,
        severity: LSPosedSignalSeverity,
        detail: String,
    ): LSPosedSignal {
        return LSPosedSignal(
            id = id,
            label = label,
            value = value,
            group = LSPosedSignalGroup.POLICY,
            severity = severity,
            detail = detail,
        )
    }
}
