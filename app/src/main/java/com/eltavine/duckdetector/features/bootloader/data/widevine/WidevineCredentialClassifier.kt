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

package com.eltavine.duckdetector.features.bootloader.data.widevine

import java.util.Locale

internal class WidevineCredentialClassifier {

    fun classify(
        snapshot: WidevineCredentialSnapshot,
        bootContext: WidevineBootContext,
    ): WidevineCredentialAssessment {
        val credentialFinding = classifyCredential(snapshot, bootContext)
        val parityFinding = classifyParity(snapshot)
        val findings = listOf(credentialFinding, parityFinding)
        val methodSeverity = findings.map { it.severity }.highestSeverity()
        return WidevineCredentialAssessment(
            findings = findings,
            methodSummary = when (methodSeverity) {
                WidevineAssessmentSeverity.DANGER -> "Credential anomaly"
                WidevineAssessmentSeverity.WARNING -> "Needs review"
                WidevineAssessmentSeverity.SUPPORT -> "Partial"
                WidevineAssessmentSeverity.SAFE -> "Consistent"
            },
            methodSeverity = methodSeverity,
            methodDetail = findings.joinToString("\n") { finding ->
                "${finding.label}: ${finding.value}. ${finding.detail}"
            },
            impact = buildImpact(credentialFinding, parityFinding, bootContext),
        )
    }

    private fun classifyCredential(
        snapshot: WidevineCredentialSnapshot,
        bootContext: WidevineBootContext,
    ): WidevineAssessmentFinding {
        if (snapshot.schemeSupported != true) {
            return credentialFinding(
                value = if (snapshot.schemeSupported == false) "Unsupported" else "Unavailable",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = "Widevine support could not be established; no credential verdict was emitted.",
            )
        }

        val securityLevel = snapshot.javaSecurityLevel.normalizedSecurityLevel()
        val systemId = snapshot.javaSystemId.normalizedSystemId()
        if (snapshot.javaSecurityLevel.status != WidevinePropertyStatus.AVAILABLE ||
            snapshot.javaSystemId.status != WidevinePropertyStatus.AVAILABLE ||
            securityLevel == null ||
            systemId == null
        ) {
            return credentialFinding(
                value = "Properties unavailable",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = buildDetail(snapshot, bootContext),
            )
        }

        val advertisedL1 = securityLevel == ADVERTISED_L1
        val sentinel = advertisedL1 && systemId == WIDEVINE_SENTINEL_SYSTEM_ID
        val sessionDowngrade = advertisedL1 &&
            snapshot.sessionStatus == WidevineOperationStatus.SUCCESS &&
            snapshot.actualSessionSecurityLevel != null &&
            snapshot.actualSessionSecurityLevel != WidevineSessionSecurityLevel.HW_SECURE_ALL
        val hardSessionFailure = advertisedL1 && snapshot.sessionStatus in setOf(
            WidevineOperationStatus.NOT_PROVISIONED,
            WidevineOperationStatus.UNSUPPORTED,
            WidevineOperationStatus.FAILURE,
        )
        val sessionLevelFailure = advertisedL1 && snapshot.errors.any { error ->
            error.stage == WidevineDrmErrorStage.SESSION_SECURITY_LEVEL && error.transient != true
        }
        val sentinelCredentialFailure = sentinel && (
            snapshot.credentialStatus == WidevineOperationStatus.SUCCESS &&
                snapshot.credentialAvailable == false ||
                snapshot.credentialStatus == WidevineOperationStatus.NOT_PROVISIONED ||
                snapshot.credentialStatus == WidevineOperationStatus.FAILURE ||
                snapshot.keyRequestStatus == WidevineOperationStatus.NOT_PROVISIONED ||
                snapshot.keyRequestStatus == WidevineOperationStatus.FAILURE
            )
        val independentlyConfirmedUnlock = sentinel && bootContext.rootOfTrustUnlocked

        val detail = buildDetail(snapshot, bootContext)
        return when {
            sessionDowngrade -> credentialFinding(
                value = "Session downgrade",
                severity = WidevineAssessmentSeverity.DANGER,
                detail = detail,
            )

            hardSessionFailure -> credentialFinding(
                value = "Hardware session failed",
                severity = WidevineAssessmentSeverity.DANGER,
                detail = detail,
            )

            sentinelCredentialFailure -> credentialFinding(
                value = "Invalid credential",
                severity = WidevineAssessmentSeverity.DANGER,
                detail = detail,
            )

            independentlyConfirmedUnlock -> credentialFinding(
                value = "Unlock impact confirmed",
                severity = WidevineAssessmentSeverity.DANGER,
                detail = detail,
            )

            sentinel -> credentialFinding(
                value = "Sentinel system ID",
                severity = WidevineAssessmentSeverity.WARNING,
                detail = detail,
            )

            sessionLevelFailure -> credentialFinding(
                value = "Session level unavailable",
                severity = WidevineAssessmentSeverity.WARNING,
                detail = detail,
            )

            snapshot.sessionStatus == WidevineOperationStatus.RESOURCE_BUSY ||
                snapshot.sessionStatus == WidevineOperationStatus.TRANSIENT_ERROR ->
                credentialFinding(
                    value = "Inconclusive",
                    severity = WidevineAssessmentSeverity.SUPPORT,
                    detail = detail,
                )

            snapshot.sessionStatus == WidevineOperationStatus.SUCCESS &&
                snapshot.actualSessionSecurityLevel != null &&
                snapshot.credentialStatus == WidevineOperationStatus.SUCCESS &&
                snapshot.credentialAvailable == true &&
                snapshot.keyRequestStatus == WidevineOperationStatus.SUCCESS ->
                credentialFinding(
                    value = "Consistent",
                    severity = WidevineAssessmentSeverity.SAFE,
                    detail = detail,
                )

            else -> credentialFinding(
                value = "Partial",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = detail,
            )
        }
    }

    private fun classifyParity(
        snapshot: WidevineCredentialSnapshot,
    ): WidevineAssessmentFinding {
        if (!snapshot.native.available) {
            return parityFinding(
                value = "Native unavailable",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = "The NDK property path was unavailable, so Java/native parity was not evaluated.",
            )
        }

        val javaSecurity = snapshot.javaSecurityLevel.normalizedSecurityLevel()
        val nativeSecurity = snapshot.native.securityLevel.normalizedSecurityLevel()
        val javaSystemId = snapshot.javaSystemId.normalizedSystemId()
        val nativeSystemId = snapshot.native.systemId.normalizedSystemId()
        val securityComparable = snapshot.javaSecurityLevel.status == WidevinePropertyStatus.AVAILABLE &&
            snapshot.native.securityLevel.status == WidevinePropertyStatus.AVAILABLE
        val systemIdComparable = snapshot.javaSystemId.status == WidevinePropertyStatus.AVAILABLE &&
            snapshot.native.systemId.status == WidevinePropertyStatus.AVAILABLE
        val securityMismatch = securityComparable && javaSecurity != nativeSecurity
        val systemIdMismatch = systemIdComparable && javaSystemId != nativeSystemId

        if (securityMismatch || systemIdMismatch) {
            val fields = buildList {
                if (securityMismatch) add("securityLevel")
                if (systemIdMismatch) add("systemId")
            }
            return parityFinding(
                value = "Mismatch",
                severity = WidevineAssessmentSeverity.WARNING,
                detail = "Java and NDK reads differ for ${fields.joinToString(", ")}; a hook, spoof, or framework inconsistency is possible. " +
                    parityValues(snapshot),
            )
        }

        if (securityComparable && systemIdComparable) {
            return parityFinding(
                value = "Aligned",
                severity = WidevineAssessmentSeverity.SAFE,
                detail = parityValues(snapshot),
            )
        }

        return parityFinding(
            value = "Partial",
            severity = WidevineAssessmentSeverity.SUPPORT,
            detail = "One or more vendor properties were unavailable on either the Java or NDK path. " +
                parityValues(snapshot),
        )
    }

    private fun buildDetail(
        snapshot: WidevineCredentialSnapshot,
        bootContext: WidevineBootContext,
    ): String {
        return buildString {
            append("Advertised level: ")
            append(snapshot.javaSecurityLevel.normalizedSecurityLevel().displayValue())
            append("; Java system ID: ")
            append(snapshot.javaSystemId.normalizedSystemId().displayValue())
            append("; actual session: ")
            append(snapshot.actualSessionSecurityLevel?.name ?: snapshot.sessionStatus.name)
            append("; credential availability: ")
            append(
                when {
                    snapshot.credentialStatus != WidevineOperationStatus.SUCCESS ->
                        snapshot.credentialStatus.name

                    snapshot.credentialAvailable == true -> "AVAILABLE"
                    else -> "UNAVAILABLE"
                },
            )
            append("; local key request: ")
            append(snapshot.keyRequestStatus.name)
            append("; boot context: ")
            append(
                when {
                    bootContext.rootOfTrustUnlocked -> "RootOfTrust confirms unlocked"
                    bootContext.bootStateAppearsLocked -> "boot state appears locked"
                    else -> "boot state is inconclusive"
                },
            )
            if (snapshot.errors.isNotEmpty()) {
                append("; sanitized errors: ")
                append(snapshot.errors.joinToString(", ") { it.numericDescription() })
            }
            append('.')
        }
    }

    private fun parityValues(snapshot: WidevineCredentialSnapshot): String {
        return "securityLevel(Java=${snapshot.javaSecurityLevel.normalizedSecurityLevel().displayValue()}, " +
            "NDK=${snapshot.native.securityLevel.normalizedSecurityLevel().displayValue()}); " +
            "systemId(Java=${snapshot.javaSystemId.normalizedSystemId().displayValue()}, " +
            "NDK=${snapshot.native.systemId.normalizedSystemId().displayValue()})."
    }

    private fun buildImpact(
        credential: WidevineAssessmentFinding,
        parity: WidevineAssessmentFinding,
        bootContext: WidevineBootContext,
    ): WidevineAssessmentFinding? {
        return when {
            credential.severity == WidevineAssessmentSeverity.DANGER ->
                WidevineAssessmentFinding(
                    id = "widevine_impact",
                    label = "Widevine impact",
                    value = "Operational inconsistency",
                    severity = WidevineAssessmentSeverity.DANGER,
                    detail = "The advertised L1 state conflicts with independent credential, session, or RootOfTrust evidence. This confirms a DRM credential anomaly, not a standalone bootloader-state verdict.",
                )

            credential.severity == WidevineAssessmentSeverity.WARNING ->
                WidevineAssessmentFinding(
                    id = "widevine_impact",
                    label = "Widevine impact",
                    value = "Credential anomaly",
                    severity = WidevineAssessmentSeverity.WARNING,
                    detail = if (bootContext.bootStateAppearsLocked) {
                        "A locked-looking boot state with the exact Widevine sentinel may reflect historical unlocking, ROM conversion, spoofing, or an OEM provisioning defect."
                    } else {
                        "The exact Widevine sentinel is suspicious but does not independently establish the current bootloader lock state."
                    },
                )

            parity.severity == WidevineAssessmentSeverity.WARNING ->
                WidevineAssessmentFinding(
                    id = "widevine_impact",
                    label = "Widevine impact",
                    value = "Cross-API mismatch",
                    severity = WidevineAssessmentSeverity.WARNING,
                    detail = "Java/native disagreement can indicate a MediaDrm hook, spoof, or vendor framework inconsistency.",
                )

            else -> null
        }
    }

    private fun credentialFinding(
        value: String,
        severity: WidevineAssessmentSeverity,
        detail: String,
    ): WidevineAssessmentFinding {
        return WidevineAssessmentFinding(
            id = "widevine_credential",
            label = "Widevine credential",
            value = value,
            severity = severity,
            detail = detail,
        )
    }

    private fun parityFinding(
        value: String,
        severity: WidevineAssessmentSeverity,
        detail: String,
    ): WidevineAssessmentFinding {
        return WidevineAssessmentFinding(
            id = "widevine_property_parity",
            label = "Widevine Java/native parity",
            value = value,
            severity = severity,
            detail = detail,
        )
    }

    private fun WidevinePropertyRead.normalizedSecurityLevel(): String? {
        return value?.trim()?.takeIf { it.isNotEmpty() }?.uppercase(Locale.ROOT)
    }

    private fun WidevinePropertyRead.normalizedSystemId(): String? {
        return value?.trim()?.takeIf { it.isNotEmpty() }
    }

    private fun String?.displayValue(): String = this ?: "unavailable"

    private fun WidevineDrmError.numericDescription(): String {
        return buildString {
            append(stage.name)
            append('(')
            append(kind.name)
            errorCode?.let { append(",code=$it") }
            vendorError?.let { append(",vendor=$it") }
            oemError?.let { append(",oem=$it") }
            errorContext?.let { append(",context=$it") }
            transient?.let { append(",transient=$it") }
            append(')')
        }
    }

    private fun List<WidevineAssessmentSeverity>.highestSeverity(): WidevineAssessmentSeverity {
        return when {
            WidevineAssessmentSeverity.DANGER in this -> WidevineAssessmentSeverity.DANGER
            WidevineAssessmentSeverity.WARNING in this -> WidevineAssessmentSeverity.WARNING
            WidevineAssessmentSeverity.SUPPORT in this -> WidevineAssessmentSeverity.SUPPORT
            else -> WidevineAssessmentSeverity.SAFE
        }
    }

    private companion object {
        const val ADVERTISED_L1 = "L1"
    }
}
