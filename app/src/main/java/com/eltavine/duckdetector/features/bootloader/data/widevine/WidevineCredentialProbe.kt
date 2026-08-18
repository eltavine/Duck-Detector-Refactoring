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

import android.media.MediaDrm
import android.media.MediaDrm.MediaDrmStateException
import android.media.MediaDrmException
import android.media.NotProvisionedException
import android.media.ResourceBusyException
import android.media.UnsupportedSchemeException
import android.os.Build
import java.util.UUID

internal fun interface WidevineCredentialSource {
    fun collect(): WidevineCredentialSnapshot
}

internal interface WidevineMediaDrmFactory {
    fun isCryptoSchemeSupported(): Boolean

    fun create(): WidevineMediaDrmClient
}

internal interface WidevineMediaDrmClient : AutoCloseable {
    fun getPropertyString(name: String): String

    fun openHardwareSecureAllSession(): ByteArray

    fun getSecurityLevel(sessionId: ByteArray): WidevineSessionSecurityLevel

    fun hasDeviceUniqueId(): Boolean

    fun generateTestKeyRequest(sessionId: ByteArray)

    fun closeSession(sessionId: ByteArray)
}

internal class WidevineCredentialProbe(
    private val mediaDrmFactory: WidevineMediaDrmFactory = AndroidWidevineMediaDrmFactory,
    private val nativePropertyReader: WidevineNativePropertyReader = WidevineNativeBridge(),
) : WidevineCredentialSource {

    override fun collect(): WidevineCredentialSnapshot {
        val errors = mutableListOf<WidevineDrmError>()
        val supported = try {
            mediaDrmFactory.isCryptoSchemeSupported()
        } catch (throwable: Throwable) {
            errors += sanitizeError(WidevineDrmErrorStage.SUPPORT_CHECK, throwable)
            return WidevineCredentialSnapshot(errors = errors)
        }
        if (!supported) {
            return WidevineCredentialSnapshot(schemeSupported = false)
        }

        val nativeSnapshot = nativePropertyReader.readProperties()
        var javaSecurityLevel = WidevinePropertyRead()
        var javaSystemId = WidevinePropertyRead()
        var sessionStatus = WidevineOperationStatus.NOT_ATTEMPTED
        var actualSecurityLevel: WidevineSessionSecurityLevel? = null
        var credentialStatus = WidevineOperationStatus.NOT_ATTEMPTED
        var credentialAvailable: Boolean? = null
        var keyRequestStatus = WidevineOperationStatus.NOT_ATTEMPTED
        var mediaDrm: WidevineMediaDrmClient? = null
        var sessionId: ByteArray? = null

        try {
            mediaDrm = try {
                mediaDrmFactory.create()
            } catch (throwable: Throwable) {
                errors += sanitizeError(WidevineDrmErrorStage.CREATE, throwable)
                null
            }

            if (mediaDrm != null) {
                javaSecurityLevel = readProperty(
                    stage = WidevineDrmErrorStage.JAVA_SECURITY_LEVEL,
                    errors = errors,
                ) {
                    mediaDrm.getPropertyString(PROPERTY_SECURITY_LEVEL)
                }
                javaSystemId = readProperty(
                    stage = WidevineDrmErrorStage.JAVA_SYSTEM_ID,
                    errors = errors,
                ) {
                    mediaDrm.getPropertyString(PROPERTY_SYSTEM_ID)
                }

                try {
                    sessionId = mediaDrm.openHardwareSecureAllSession()
                    sessionStatus = WidevineOperationStatus.SUCCESS
                } catch (throwable: Throwable) {
                    val error = sanitizeError(WidevineDrmErrorStage.SESSION_OPEN, throwable)
                    errors += error
                    sessionStatus = error.toOperationStatus()
                }

                sessionId?.let { openedSession ->
                    try {
                        actualSecurityLevel = mediaDrm.getSecurityLevel(openedSession)
                    } catch (throwable: Throwable) {
                        errors += sanitizeError(
                            WidevineDrmErrorStage.SESSION_SECURITY_LEVEL,
                            throwable,
                        )
                    }
                }

                try {
                    credentialAvailable = mediaDrm.hasDeviceUniqueId()
                    credentialStatus = WidevineOperationStatus.SUCCESS
                } catch (throwable: Throwable) {
                    val error = sanitizeError(
                        WidevineDrmErrorStage.CREDENTIAL_AVAILABILITY,
                        throwable,
                    )
                    errors += error
                    credentialStatus = error.toOperationStatus()
                }

                sessionId?.let { openedSession ->
                    try {
                        mediaDrm.generateTestKeyRequest(openedSession)
                        keyRequestStatus = WidevineOperationStatus.SUCCESS
                    } catch (throwable: Throwable) {
                        val error = sanitizeError(WidevineDrmErrorStage.KEY_REQUEST, throwable)
                        errors += error
                        keyRequestStatus = error.toOperationStatus()
                    }
                }
            }
        } finally {
            val client = mediaDrm
            val openedSession = sessionId
            if (client != null && openedSession != null) {
                try {
                    client.closeSession(openedSession)
                } catch (throwable: Throwable) {
                    errors += sanitizeError(WidevineDrmErrorStage.SESSION_CLOSE, throwable)
                }
            }
            if (client != null) {
                try {
                    client.close()
                } catch (throwable: Throwable) {
                    errors += sanitizeError(WidevineDrmErrorStage.RELEASE, throwable)
                }
            }
        }

        return WidevineCredentialSnapshot(
            schemeSupported = true,
            javaSecurityLevel = javaSecurityLevel,
            javaSystemId = javaSystemId,
            native = nativeSnapshot,
            sessionStatus = sessionStatus,
            actualSessionSecurityLevel = actualSecurityLevel,
            credentialStatus = credentialStatus,
            credentialAvailable = credentialAvailable,
            keyRequestStatus = keyRequestStatus,
            errors = errors.toList(),
        )
    }

    private fun readProperty(
        stage: WidevineDrmErrorStage,
        errors: MutableList<WidevineDrmError>,
        block: () -> String,
    ): WidevinePropertyRead {
        return try {
            WidevinePropertyRead(
                status = WidevinePropertyStatus.AVAILABLE,
                value = block(),
            )
        } catch (throwable: Throwable) {
            val error = sanitizeError(stage, throwable)
            errors += error
            WidevinePropertyRead(
                status = if (error.kind == WidevineDrmErrorKind.UNSUPPORTED_PROPERTY) {
                    WidevinePropertyStatus.UNSUPPORTED
                } else {
                    WidevinePropertyStatus.ERROR
                },
            )
        }
    }

    private fun sanitizeError(
        stage: WidevineDrmErrorStage,
        throwable: Throwable,
    ): WidevineDrmError {
        val stateException = throwable as? MediaDrmStateException
        val mediaDrmException = throwable as? MediaDrmException
        return WidevineDrmError(
            stage = stage,
            kind = when {
                throwable is UnsupportedSchemeException -> WidevineDrmErrorKind.UNSUPPORTED_SCHEME
                throwable is NotProvisionedException -> WidevineDrmErrorKind.NOT_PROVISIONED
                throwable is ResourceBusyException -> WidevineDrmErrorKind.RESOURCE_BUSY
                throwable is IllegalArgumentException && stage.isPropertyStage() ->
                    WidevineDrmErrorKind.UNSUPPORTED_PROPERTY

                throwable is UnsupportedOperationException && stage.isPropertyStage() ->
                    WidevineDrmErrorKind.UNSUPPORTED_PROPERTY

                stateException != null -> WidevineDrmErrorKind.STATE
                else -> WidevineDrmErrorKind.RUNTIME
            },
            errorCode = stateException?.sanitizedErrorCode(),
            vendorError = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                mediaDrmException?.vendorError
            } else {
                null
            },
            oemError = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                mediaDrmException?.oemError
            } else {
                null
            },
            errorContext = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                mediaDrmException?.errorContext
            } else {
                null
            },
            transient = if (stateException != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                stateException.isTransient
            } else {
                null
            },
        )
    }

    private fun MediaDrmStateException.sanitizedErrorCode(): Int? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return errorCode
        }
        val match = LEGACY_DIAGNOSTIC_ERROR.find(diagnosticInfo) ?: return null
        val magnitude = match.groupValues[2].toIntOrNull() ?: return null
        return if (match.groupValues[1].isNotEmpty()) -magnitude else magnitude
    }

    private fun WidevineDrmErrorStage.isPropertyStage(): Boolean {
        return this == WidevineDrmErrorStage.JAVA_SECURITY_LEVEL ||
            this == WidevineDrmErrorStage.JAVA_SYSTEM_ID
    }

    private fun WidevineDrmError.toOperationStatus(): WidevineOperationStatus {
        return when {
            kind == WidevineDrmErrorKind.UNSUPPORTED_SCHEME ||
                kind == WidevineDrmErrorKind.UNSUPPORTED_PROPERTY ->
                WidevineOperationStatus.UNSUPPORTED

            kind == WidevineDrmErrorKind.NOT_PROVISIONED ->
                WidevineOperationStatus.NOT_PROVISIONED

            kind == WidevineDrmErrorKind.RESOURCE_BUSY ->
                WidevineOperationStatus.RESOURCE_BUSY

            transient == true -> WidevineOperationStatus.TRANSIENT_ERROR
            else -> WidevineOperationStatus.FAILURE
        }
    }

    private companion object {
        const val PROPERTY_SECURITY_LEVEL = "securityLevel"
        const val PROPERTY_SYSTEM_ID = "systemId"
        val LEGACY_DIAGNOSTIC_ERROR = Regex("error_(neg_)?(\\d+)")
    }
}

private object AndroidWidevineMediaDrmFactory : WidevineMediaDrmFactory {
    private val widevineUuid = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    override fun isCryptoSchemeSupported(): Boolean {
        return MediaDrm.isCryptoSchemeSupported(widevineUuid)
    }

    override fun create(): WidevineMediaDrmClient {
        return AndroidWidevineMediaDrmClient(MediaDrm(widevineUuid))
    }
}

private class AndroidWidevineMediaDrmClient(
    private val mediaDrm: MediaDrm,
) : WidevineMediaDrmClient {

    override fun getPropertyString(name: String): String = mediaDrm.getPropertyString(name)

    override fun openHardwareSecureAllSession(): ByteArray {
        return mediaDrm.openSession(MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL)
    }

    override fun getSecurityLevel(sessionId: ByteArray): WidevineSessionSecurityLevel {
        return when (mediaDrm.getSecurityLevel(sessionId)) {
            MediaDrm.SECURITY_LEVEL_SW_SECURE_CRYPTO ->
                WidevineSessionSecurityLevel.SW_SECURE_CRYPTO

            MediaDrm.SECURITY_LEVEL_SW_SECURE_DECODE ->
                WidevineSessionSecurityLevel.SW_SECURE_DECODE

            MediaDrm.SECURITY_LEVEL_HW_SECURE_CRYPTO ->
                WidevineSessionSecurityLevel.HW_SECURE_CRYPTO

            MediaDrm.SECURITY_LEVEL_HW_SECURE_DECODE ->
                WidevineSessionSecurityLevel.HW_SECURE_DECODE

            MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL ->
                WidevineSessionSecurityLevel.HW_SECURE_ALL

            else -> WidevineSessionSecurityLevel.UNKNOWN
        }
    }

    override fun hasDeviceUniqueId(): Boolean {
        return mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID).isNotEmpty()
    }

    override fun generateTestKeyRequest(sessionId: ByteArray) {
        mediaDrm.getKeyRequest(
            sessionId,
            TEST_PSSH,
            TEST_MIME_TYPE,
            MediaDrm.KEY_TYPE_STREAMING,
            hashMapOf(),
        )
    }

    override fun closeSession(sessionId: ByteArray) {
        mediaDrm.closeSession(sessionId)
    }

    override fun close() {
        mediaDrm.close()
    }

    private companion object {
        const val TEST_MIME_TYPE = "video/mp4"

        // Common Encryption PSSH v0 with the Widevine system ID and a fixed non-secret test KID.
        val TEST_PSSH = intArrayOf(
            0x00, 0x00, 0x00, 0x32,
            0x70, 0x73, 0x73, 0x68,
            0x00, 0x00, 0x00, 0x00,
            0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce,
            0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed,
            0x00, 0x00, 0x00, 0x12,
            0x12, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ).map(Int::toByte).toByteArray()
    }
}
