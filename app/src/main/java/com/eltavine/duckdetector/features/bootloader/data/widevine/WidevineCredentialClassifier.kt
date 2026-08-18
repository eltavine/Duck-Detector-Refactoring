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
                WidevineAssessmentSeverity.DANGER -> "DRM inconsistency"
                WidevineAssessmentSeverity.WARNING -> "Needs review"
                WidevineAssessmentSeverity.SUPPORT -> "Partial"
                WidevineAssessmentSeverity.SAFE -> "Consistent"
            },
            methodSeverity = methodSeverity,
            methodDetail = findings.joinToString("\n") { finding ->
                "${finding.label}: ${finding.value}. ${finding.detail}"
            },
            impact = buildImpact(credentialFinding, parityFinding),
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
            securityLevel == null
        ) {
            return credentialFinding(
                value = "Security level unavailable",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = buildDetail(snapshot, bootContext),
            )
        }

        val advertisedL1 = securityLevel == ADVERTISED_L1
        val systemIdAvailable = snapshot.javaSystemId.status == WidevinePropertyStatus.AVAILABLE &&
            systemId != null
        val sentinel = snapshot.javaSecurityLevel.status == WidevinePropertyStatus.AVAILABLE &&
            snapshot.javaSystemId.status == WidevinePropertyStatus.AVAILABLE &&
            snapshot.javaSecurityLevel.value == ADVERTISED_L1 &&
            snapshot.javaSystemId.value == WIDEVINE_SENTINEL_SYSTEM_ID
        val sessionDowngrade = advertisedL1 &&
            snapshot.hardwareSecureAllSupported == true &&
            snapshot.sessionStatus == WidevineOperationStatus.SUCCESS &&
            snapshot.actualSessionSecurityLevel.isKnownBelowHardwareSecureAll()
        val constrainedMaximumSession = advertisedL1 &&
            snapshot.hardwareSecureAllSupported != true &&
            snapshot.sessionStatus == WidevineOperationStatus.SUCCESS &&
            snapshot.actualSessionSecurityLevel.isKnownBelowHardwareSecureAll()
        val inconclusiveSessionFailure = advertisedL1 && snapshot.sessionStatus in setOf(
            WidevineOperationStatus.NOT_PROVISIONED,
            WidevineOperationStatus.UNSUPPORTED,
            WidevineOperationStatus.FAILURE,
        )
        val sessionLevelFailure = advertisedL1 && snapshot.errors.any { error ->
            error.stage == WidevineDrmErrorStage.SESSION_SECURITY_LEVEL && error.transient != true
        }

        val detail = buildDetail(snapshot, bootContext)
        return when {
            sentinel && sessionDowngrade -> credentialFinding(
                value = "Corroborated anomaly",
                severity = WidevineAssessmentSeverity.DANGER,
                detail = detail,
            )

            sentinel -> credentialFinding(
                value = "Sentinel system ID",
                severity = WidevineAssessmentSeverity.WARNING,
                detail = detail,
            )

            sessionDowngrade -> credentialFinding(
                value = "Lower security session",
                severity = WidevineAssessmentSeverity.WARNING,
                detail = detail,
            )

            snapshot.sessionStatus == WidevineOperationStatus.RESOURCE_BUSY ||
                snapshot.sessionStatus == WidevineOperationStatus.TRANSIENT_ERROR ||
                inconclusiveSessionFailure ->
                credentialFinding(
                    value = "Session inconclusive",
                    severity = WidevineAssessmentSeverity.SUPPORT,
                    detail = detail,
                )

            sessionLevelFailure -> credentialFinding(
                value = "Session level unavailable",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = detail,
            )

            constrainedMaximumSession -> credentialFinding(
                value = "Maximum security constrained",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = detail,
            )

            !systemIdAvailable -> credentialFinding(
                value = "System ID unavailable",
                severity = WidevineAssessmentSeverity.SUPPORT,
                detail = detail,
            )

            advertisedL1 &&
                snapshot.hardwareSecureAllSupported == true &&
                snapshot.sessionStatus == WidevineOperationStatus.SUCCESS &&
                snapshot.actualSessionSecurityLevel == WidevineSessionSecurityLevel.HW_SECURE_ALL &&
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

        val securityComparable = snapshot.javaSecurityLevel.status == WidevinePropertyStatus.AVAILABLE &&
            snapshot.native.securityLevel.status == WidevinePropertyStatus.AVAILABLE
        val systemIdComparable = snapshot.javaSystemId.status == WidevinePropertyStatus.AVAILABLE &&
            snapshot.native.systemId.status == WidevinePropertyStatus.AVAILABLE
        val securityMismatch = securityComparable &&
            snapshot.javaSecurityLevel.value != snapshot.native.securityLevel.value
        val systemIdMismatch = systemIdComparable &&
            snapshot.javaSystemId.value != snapshot.native.systemId.value

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
            append("; video/mp4 HW_SECURE_ALL capability: ")
            append(
                when (snapshot.hardwareSecureAllSupported) {
                    true -> "SUPPORTED"
                    false -> "UNSUPPORTED"
                    null -> "UNAVAILABLE"
                },
            )
            append("; maximum session: ")
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
                    bootContext.rootOfTrustUnlocked -> "independent RootOfTrust state is unlocked"
                    bootContext.bootStateAppearsLocked -> "independent boot state appears locked"
                    else -> "independent boot state is inconclusive"
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
    ): WidevineAssessmentFinding? {
        return when {
            credential.severity == WidevineAssessmentSeverity.DANGER ->
                WidevineAssessmentFinding(
                    id = "widevine_impact",
                    label = "Widevine impact",
                    value = "Auxiliary DRM inconsistency",
                    severity = WidevineAssessmentSeverity.DANGER,
                    detail = "The exact sentinel and a lower maximum-session level were observed despite video/mp4 HW_SECURE_ALL support. This is a critical DRM conflict, not standalone proof of the current bootloader state.",
                )

            credential.severity == WidevineAssessmentSeverity.WARNING ->
                WidevineAssessmentFinding(
                    id = "widevine_impact",
                    label = "Widevine impact",
                    value = "Auxiliary DRM signal",
                    severity = WidevineAssessmentSeverity.WARNING,
                    detail = when (credential.value) {
                        "Sentinel system ID" ->
                            "The exact Widevine sentinel requires review but does not override the current bootloader state."

                        else ->
                            "The maximum-security session resolved below HW_SECURE_ALL despite reported support; the DRM result requires review."
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

    private fun WidevineSessionSecurityLevel?.isKnownBelowHardwareSecureAll(): Boolean {
        return this == WidevineSessionSecurityLevel.SW_SECURE_CRYPTO ||
            this == WidevineSessionSecurityLevel.SW_SECURE_DECODE ||
            this == WidevineSessionSecurityLevel.HW_SECURE_CRYPTO ||
            this == WidevineSessionSecurityLevel.HW_SECURE_DECODE
    }

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
