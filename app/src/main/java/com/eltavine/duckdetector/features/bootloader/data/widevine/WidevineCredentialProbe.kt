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
import android.media.MediaDrm.SessionException
import android.media.MediaDrmThrowable
import android.media.NotProvisionedException
import android.media.ResourceBusyException
import android.media.UnsupportedSchemeException
import android.os.Build
import androidx.annotation.RequiresApi
import java.util.UUID

internal fun interface WidevineCredentialSource {
    fun collect(): WidevineCredentialSnapshot
}

internal interface WidevineMediaDrmFactory {
    fun isCryptoSchemeSupported(): Boolean

    fun isHardwareSecureAllSupported(): Boolean

    fun create(): WidevineMediaDrmClient
}

internal interface WidevineMediaDrmClient : AutoCloseable {
    fun getPropertyString(name: String): String

    fun openMaximumSecuritySession(): ByteArray

    fun getSecurityLevel(sessionId: ByteArray): WidevineSessionSecurityLevel

    fun hasDeviceUniqueId(): Boolean

    fun generateTestKeyRequest(sessionId: ByteArray)

    fun closeSession(sessionId: ByteArray)
}

internal data class WidevineDrmErrorMetadata(
    val errorCode: Int? = null,
    val vendorError: Int? = null,
    val oemError: Int? = null,
    val errorContext: Int? = null,
    val transient: Boolean? = null,
)

internal fun interface WidevineDrmErrorMetadataReader {
    fun read(throwable: Exception): WidevineDrmErrorMetadata
}

internal class WidevineCredentialProbe(
    private val mediaDrmFactory: WidevineMediaDrmFactory = AndroidWidevineMediaDrmFactory,
    private val nativePropertyReader: WidevineNativePropertyReader = WidevineNativeBridge(),
    private val errorMetadataReader: WidevineDrmErrorMetadataReader =
        AndroidWidevineDrmErrorMetadataReader,
) : WidevineCredentialSource {

    override fun collect(): WidevineCredentialSnapshot {
        val errors = mutableListOf<WidevineDrmError>()
        val supported = try {
            mediaDrmFactory.isCryptoSchemeSupported()
        } catch (throwable: Exception) {
            errors += sanitizeError(WidevineDrmErrorStage.SUPPORT_CHECK, throwable)
            return WidevineCredentialSnapshot(errors = errors)
        }
        if (!supported) {
            return WidevineCredentialSnapshot(schemeSupported = false)
        }

        val hardwareSecureAllSupported = try {
            mediaDrmFactory.isHardwareSecureAllSupported()
        } catch (throwable: Exception) {
            errors += sanitizeError(WidevineDrmErrorStage.SESSION_CAPABILITY, throwable)
            null
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
            } catch (throwable: Exception) {
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
                    val openedSession = mediaDrm.openMaximumSecuritySession()
                    if (openedSession.isEmpty()) {
                        errors += WidevineDrmError(
                            stage = WidevineDrmErrorStage.SESSION_OPEN,
                            kind = WidevineDrmErrorKind.INVALID_SESSION_ID,
                        )
                        sessionStatus = WidevineOperationStatus.FAILURE
                    } else {
                        sessionId = openedSession
                        sessionStatus = WidevineOperationStatus.SUCCESS
                    }
                } catch (throwable: Exception) {
                    val error = sanitizeError(WidevineDrmErrorStage.SESSION_OPEN, throwable)
                    errors += error
                    sessionStatus = error.toOperationStatus()
                }

                sessionId?.let { openedSession ->
                    try {
                        actualSecurityLevel = mediaDrm.getSecurityLevel(openedSession)
                    } catch (throwable: Exception) {
                        errors += sanitizeError(
                            WidevineDrmErrorStage.SESSION_SECURITY_LEVEL,
                            throwable,
                        )
                    }
                }

                try {
                    credentialAvailable = mediaDrm.hasDeviceUniqueId()
                    credentialStatus = WidevineOperationStatus.SUCCESS
                } catch (throwable: Exception) {
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
                    } catch (throwable: Exception) {
                        val error = sanitizeError(WidevineDrmErrorStage.KEY_REQUEST, throwable)
                        errors += error
                        keyRequestStatus = error.toOperationStatus()
                    }
                }
            }
        } finally {
            val client = mediaDrm
            val openedSession = sessionId
            try {
                if (client != null && openedSession != null) {
                    try {
                        client.closeSession(openedSession)
                    } catch (throwable: Exception) {
                        errors += sanitizeError(WidevineDrmErrorStage.SESSION_CLOSE, throwable)
                    } finally {
                        openedSession.fill(0)
                    }
                }
            } finally {
                if (client != null) {
                    try {
                        client.close()
                    } catch (throwable: Exception) {
                        errors += sanitizeError(WidevineDrmErrorStage.RELEASE, throwable)
                    }
                }
            }
        }

        return WidevineCredentialSnapshot(
            schemeSupported = true,
            hardwareSecureAllSupported = hardwareSecureAllSupported,
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
            val value = block()
            if (value.isValidWidevinePropertyValue()) {
                WidevinePropertyRead(
                    status = WidevinePropertyStatus.AVAILABLE,
                    value = value,
                )
            } else {
                errors += WidevineDrmError(
                    stage = stage,
                    kind = WidevineDrmErrorKind.INVALID_PROPERTY_VALUE,
                )
                WidevinePropertyRead(status = WidevinePropertyStatus.ERROR)
            }
        } catch (throwable: Exception) {
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
        throwable: Exception,
    ): WidevineDrmError {
        val stateException = throwable as? MediaDrmStateException
        val sessionException = throwable as? SessionException
        val numericMetadata = try {
            errorMetadataReader.read(throwable)
        } catch (_: Exception) {
            WidevineDrmErrorMetadata()
        }
        val unsupportedProperty = stage.isPropertyStage() && (
            throwable is IllegalArgumentException ||
                throwable is UnsupportedOperationException ||
                stateException != null &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                numericMetadata.errorCode == MediaDrm.ErrorCodes.ERROR_UNSUPPORTED_OPERATION
        )
        return WidevineDrmError(
            stage = stage,
            kind = when {
                throwable is UnsupportedSchemeException -> WidevineDrmErrorKind.UNSUPPORTED_SCHEME
                throwable is NotProvisionedException -> WidevineDrmErrorKind.NOT_PROVISIONED
                throwable is ResourceBusyException -> WidevineDrmErrorKind.RESOURCE_BUSY
                sessionException != null && numericMetadata.transient == true ->
                    WidevineDrmErrorKind.RESOURCE_BUSY

                unsupportedProperty -> WidevineDrmErrorKind.UNSUPPORTED_PROPERTY
                stateException != null || sessionException != null -> WidevineDrmErrorKind.STATE
                else -> WidevineDrmErrorKind.RUNTIME
            },
            errorCode = numericMetadata.errorCode,
            vendorError = numericMetadata.vendorError,
            oemError = numericMetadata.oemError,
            errorContext = numericMetadata.errorContext,
            transient = numericMetadata.transient,
        )
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
    }
}

private object AndroidWidevineDrmErrorMetadataReader : WidevineDrmErrorMetadataReader {

    override fun read(throwable: Exception): WidevineDrmErrorMetadata {
        val stateException = throwable as? MediaDrmStateException
        val sessionException = throwable as? SessionException
        val api34Metadata = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            Api34.read(throwable)
        } else {
            WidevineDrmErrorMetadata()
        }
        return api34Metadata.copy(
            errorCode = when {
                stateException != null -> stateException.sanitizedErrorCode()
                sessionException != null -> sessionException.sanitizedErrorCode()
                else -> null
            },
            transient = when {
                stateException != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                    stateException.isTransient

                sessionException != null -> sessionException.isTransientCompat()
                else -> null
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

    @Suppress("DEPRECATION")
    private fun SessionException.sanitizedErrorCode(): Int = errorCode

    @Suppress("DEPRECATION")
    private fun SessionException.isTransientCompat(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            isTransient
        } else {
            errorCode == SessionException.ERROR_RESOURCE_CONTENTION
        }
    }

    private val LEGACY_DIAGNOSTIC_ERROR = Regex("error_(neg_)?(\\d+)")

    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    private object Api34 {
        fun read(throwable: Throwable): WidevineDrmErrorMetadata {
            val mediaDrmThrowable = throwable as? MediaDrmThrowable
                ?: return WidevineDrmErrorMetadata()
            return WidevineDrmErrorMetadata(
                vendorError = mediaDrmThrowable.vendorError,
                oemError = mediaDrmThrowable.oemError,
                errorContext = mediaDrmThrowable.errorContext,
            )
        }
    }
}

private object AndroidWidevineMediaDrmFactory : WidevineMediaDrmFactory {
    private val widevineUuid = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    override fun isCryptoSchemeSupported(): Boolean {
        return MediaDrm.isCryptoSchemeSupported(widevineUuid)
    }

    override fun isHardwareSecureAllSupported(): Boolean {
        return MediaDrm.isCryptoSchemeSupported(
            widevineUuid,
            WIDEVINE_TEST_MIME_TYPE,
            MediaDrm.SECURITY_LEVEL_HW_SECURE_ALL,
        )
    }

    override fun create(): WidevineMediaDrmClient {
        return AndroidWidevineMediaDrmClient(MediaDrm(widevineUuid))
    }
}

private class AndroidWidevineMediaDrmClient(
    private val mediaDrm: MediaDrm,
) : WidevineMediaDrmClient {

    override fun getPropertyString(name: String): String = mediaDrm.getPropertyString(name)

    override fun openMaximumSecuritySession(): ByteArray {
        return mediaDrm.openSession()
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
        val deviceUniqueId = mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
        return try {
            deviceUniqueId.isNotEmpty()
        } finally {
            deviceUniqueId.fill(0)
        }
    }

    override fun generateTestKeyRequest(sessionId: ByteArray) {
        val request = mediaDrm.getKeyRequest(
            sessionId,
            TEST_PSSH.copyOf(),
            WIDEVINE_TEST_MIME_TYPE,
            MediaDrm.KEY_TYPE_STREAMING,
            hashMapOf(),
        )
        request.data.fill(0)
    }

    override fun closeSession(sessionId: ByteArray) {
        mediaDrm.closeSession(sessionId)
    }

    override fun close() {
        mediaDrm.close()
    }

    private companion object {
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

private const val WIDEVINE_TEST_MIME_TYPE = "video/mp4"
