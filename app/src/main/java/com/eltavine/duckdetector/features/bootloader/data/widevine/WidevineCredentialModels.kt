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

internal const val WIDEVINE_SENTINEL_SYSTEM_ID = "2147483647"
internal const val MAX_WIDEVINE_PROPERTY_VALUE_LENGTH = 64

internal fun String.isValidWidevinePropertyValue(): Boolean {
    return isNotEmpty() &&
        length <= MAX_WIDEVINE_PROPERTY_VALUE_LENGTH &&
        all { character -> character.code in 0x20..0x7e }
}

internal enum class WidevinePropertyStatus {
    NOT_ATTEMPTED,
    AVAILABLE,
    UNSUPPORTED,
    ERROR,
}

internal data class WidevinePropertyRead(
    val status: WidevinePropertyStatus = WidevinePropertyStatus.NOT_ATTEMPTED,
    val value: String? = null,
)

internal enum class WidevineOperationStatus {
    NOT_ATTEMPTED,
    SUCCESS,
    UNSUPPORTED,
    NOT_PROVISIONED,
    RESOURCE_BUSY,
    TRANSIENT_ERROR,
    FAILURE,
}

internal enum class WidevineSessionSecurityLevel {
    UNKNOWN,
    SW_SECURE_CRYPTO,
    SW_SECURE_DECODE,
    HW_SECURE_CRYPTO,
    HW_SECURE_DECODE,
    HW_SECURE_ALL,
}

internal enum class WidevineDrmErrorStage {
    SUPPORT_CHECK,
    SESSION_CAPABILITY,
    CREATE,
    JAVA_SECURITY_LEVEL,
    JAVA_SYSTEM_ID,
    SESSION_OPEN,
    SESSION_SECURITY_LEVEL,
    CREDENTIAL_AVAILABILITY,
    KEY_REQUEST,
    SESSION_CLOSE,
    RELEASE,
}

internal enum class WidevineDrmErrorKind {
    UNSUPPORTED_SCHEME,
    UNSUPPORTED_PROPERTY,
    INVALID_PROPERTY_VALUE,
    INVALID_SESSION_ID,
    NOT_PROVISIONED,
    RESOURCE_BUSY,
    STATE,
    RUNTIME,
}

/** Numeric-only error metadata. Framework diagnostic strings are never retained. */
internal data class WidevineDrmError(
    val stage: WidevineDrmErrorStage,
    val kind: WidevineDrmErrorKind,
    val errorCode: Int? = null,
    val vendorError: Int? = null,
    val oemError: Int? = null,
    val errorContext: Int? = null,
    val transient: Boolean? = null,
)

internal data class WidevineNativeSnapshot(
    val available: Boolean = false,
    val securityLevel: WidevinePropertyRead = WidevinePropertyRead(),
    val systemId: WidevinePropertyRead = WidevinePropertyRead(),
    val securityLevelStatusCode: Int? = null,
    val systemIdStatusCode: Int? = null,
)

/**
 * Contains capability state only. Device-unique IDs and opaque key-request bytes are deliberately
 * absent so they cannot cross the collection boundary.
 */
internal data class WidevineCredentialSnapshot(
    val schemeSupported: Boolean? = null,
    val hardwareSecureAllSupported: Boolean? = null,
    val javaSecurityLevel: WidevinePropertyRead = WidevinePropertyRead(),
    val javaSystemId: WidevinePropertyRead = WidevinePropertyRead(),
    val native: WidevineNativeSnapshot = WidevineNativeSnapshot(),
    val sessionStatus: WidevineOperationStatus = WidevineOperationStatus.NOT_ATTEMPTED,
    val actualSessionSecurityLevel: WidevineSessionSecurityLevel? = null,
    val credentialStatus: WidevineOperationStatus = WidevineOperationStatus.NOT_ATTEMPTED,
    val credentialAvailable: Boolean? = null,
    val keyRequestStatus: WidevineOperationStatus = WidevineOperationStatus.NOT_ATTEMPTED,
    val errors: List<WidevineDrmError> = emptyList(),
)

internal data class WidevineBootContext(
    val rootOfTrustUnlocked: Boolean,
    val bootStateAppearsLocked: Boolean,
)

internal enum class WidevineAssessmentSeverity {
    SAFE,
    WARNING,
    DANGER,
    SUPPORT,
}

internal data class WidevineAssessmentFinding(
    val id: String,
    val label: String,
    val value: String,
    val severity: WidevineAssessmentSeverity,
    val detail: String,
)

internal data class WidevineCredentialAssessment(
    val findings: List<WidevineAssessmentFinding>,
    val methodSummary: String,
    val methodSeverity: WidevineAssessmentSeverity,
    val methodDetail: String,
    val impact: WidevineAssessmentFinding? = null,
) {
    val anomalyCount: Int
        get() = findings.count {
            it.severity == WidevineAssessmentSeverity.WARNING ||
                it.severity == WidevineAssessmentSeverity.DANGER
        }
}
