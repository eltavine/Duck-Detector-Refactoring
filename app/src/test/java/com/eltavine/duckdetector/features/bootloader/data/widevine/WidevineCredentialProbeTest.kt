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

import android.media.MediaDrm.SessionException
import android.media.NotProvisionedException
import android.media.ResourceBusyException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WidevineCredentialProbeTest {

    @Test
    fun `successful probe closes session and MediaDrm without retaining opaque data`() {
        val client = FakeMediaDrmClient()
        val probe = probe(client)

        val snapshot = probe.collect()

        assertEquals(true, snapshot.hardwareSecureAllSupported)
        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.sessionStatus)
        assertEquals(WidevineSessionSecurityLevel.HW_SECURE_ALL, snapshot.actualSessionSecurityLevel)
        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.credentialStatus)
        assertEquals(true, snapshot.credentialAvailable)
        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.keyRequestStatus)
        assertTrue(client.deviceUniqueIdChecked)
        assertTrue(client.keyRequestGenerated)
        assertTrue(client.sessionClosed)
        assertTrue(client.closed)
        assertTrue(client.openedSession?.all { it == 0.toByte() } == true)
        assertFalse(
            WidevineCredentialSnapshot::class.java.declaredFields.any { field ->
                field.name.contains("uniqueId", ignoreCase = true) ||
                    field.name.contains("requestData", ignoreCase = true)
            },
        )
    }

    @Test
    fun `resource busy session is inconclusive and MediaDrm is still closed`() {
        val client = FakeMediaDrmClient(
            openError = ResourceBusyException("busy"),
        )

        val snapshot = probe(client).collect()

        assertEquals(WidevineOperationStatus.RESOURCE_BUSY, snapshot.sessionStatus)
        assertFalse(client.sessionClosed)
        assertTrue(client.closed)
        assertEquals(WidevineDrmErrorKind.RESOURCE_BUSY, snapshot.errors.single().kind)
    }

    @Test
    @Suppress("DEPRECATION")
    fun `session exception resource contention is transient and sanitized`() {
        val client = FakeMediaDrmClient(
            openError = SessionException(
                SessionException.ERROR_RESOURCE_CONTENTION,
                "sensitive vendor text",
            ),
        )

        val snapshot = probe(
            client = client,
            errorMetadataReader = WidevineDrmErrorMetadataReader {
                WidevineDrmErrorMetadata(
                    errorCode = SessionException.ERROR_RESOURCE_CONTENTION,
                    transient = true,
                )
            },
        ).collect()

        assertEquals(WidevineOperationStatus.RESOURCE_BUSY, snapshot.sessionStatus)
        assertEquals(WidevineDrmErrorKind.RESOURCE_BUSY, snapshot.errors.single().kind)
        assertEquals(SessionException.ERROR_RESOURCE_CONTENTION, snapshot.errors.single().errorCode)
        assertEquals(true, snapshot.errors.single().transient)
        assertFalse(snapshot.toString().contains("sensitive vendor text"))
        assertTrue(client.closed)
    }

    @Test
    fun `key request provisioning failure is classified without retaining message`() {
        val client = FakeMediaDrmClient(
            keyRequestError = NotProvisionedException("sensitive vendor text"),
        )

        val snapshot = probe(client).collect()

        assertEquals(WidevineOperationStatus.NOT_PROVISIONED, snapshot.keyRequestStatus)
        assertEquals(WidevineDrmErrorKind.NOT_PROVISIONED, snapshot.errors.single().kind)
        assertFalse(snapshot.toString().contains("sensitive vendor text"))
        assertTrue(client.sessionClosed)
        assertTrue(client.closed)
    }

    @Test
    fun `session close failure is sanitized and does not skip MediaDrm release`() {
        val client = FakeMediaDrmClient(
            closeSessionError = IllegalStateException("sensitive close text"),
        )

        val snapshot = probe(client).collect()

        assertTrue(client.sessionCloseAttempted)
        assertTrue(client.closed)
        assertTrue(client.openedSession?.all { it == 0.toByte() } == true)
        assertEquals(WidevineDrmErrorStage.SESSION_CLOSE, snapshot.errors.single().stage)
        assertEquals(WidevineDrmErrorKind.RUNTIME, snapshot.errors.single().kind)
        assertFalse(snapshot.toString().contains("sensitive close text"))
    }

    @Test
    fun `fatal session close error still attempts MediaDrm release and propagates`() {
        val client = FakeMediaDrmClient(
            closeSessionError = AssertionError("fatal close"),
        )

        try {
            probe(client).collect()
            throw AssertionError("Expected close error to propagate")
        } catch (error: AssertionError) {
            assertEquals("fatal close", error.message)
        }

        assertTrue(client.sessionCloseAttempted)
        assertTrue(client.closed)
        assertTrue(client.openedSession?.all { it == 0.toByte() } == true)
    }

    @Test
    fun `unknown private properties are support state rather than failure verdict`() {
        val client = FakeMediaDrmClient(propertyError = IllegalArgumentException("unknown"))

        val snapshot = probe(client).collect()

        assertEquals(WidevinePropertyStatus.UNSUPPORTED, snapshot.javaSecurityLevel.status)
        assertEquals(WidevinePropertyStatus.UNSUPPORTED, snapshot.javaSystemId.status)
        assertEquals(2, snapshot.errors.count {
            it.kind == WidevineDrmErrorKind.UNSUPPORTED_PROPERTY
        })
        assertTrue(client.closed)
    }

    @Test
    fun `oversized private property is rejected without retaining its value`() {
        val oversizedValue = "x".repeat(MAX_WIDEVINE_PROPERTY_VALUE_LENGTH + 1)
        val client = FakeMediaDrmClient(systemIdValue = oversizedValue)

        val snapshot = probe(client).collect()

        assertEquals(WidevinePropertyStatus.ERROR, snapshot.javaSystemId.status)
        assertEquals(null, snapshot.javaSystemId.value)
        assertTrue(snapshot.errors.any { error ->
            error.stage == WidevineDrmErrorStage.JAVA_SYSTEM_ID &&
                error.kind == WidevineDrmErrorKind.INVALID_PROPERTY_VALUE
        })
        assertFalse(snapshot.toString().contains(oversizedValue))
        assertTrue(client.closed)
    }

    @Test
    fun `unsupported scheme skips Java and native collection`() {
        var nativeRead = false
        val probe = WidevineCredentialProbe(
            mediaDrmFactory = object : WidevineMediaDrmFactory {
                override fun isCryptoSchemeSupported(): Boolean = false

                override fun isHardwareSecureAllSupported(): Boolean {
                    throw AssertionError("capability check must not be called")
                }

                override fun create(): WidevineMediaDrmClient {
                    throw AssertionError("create must not be called")
                }
            },
            nativePropertyReader = WidevineNativePropertyReader {
                nativeRead = true
                WidevineNativeSnapshot()
            },
        )

        val snapshot = probe.collect()

        assertEquals(false, snapshot.schemeSupported)
        assertFalse(nativeRead)
    }

    @Test
    fun `capability check failure is sanitized without aborting collection`() {
        val client = FakeMediaDrmClient()

        val snapshot = probe(
            client = client,
            capabilityError = IllegalStateException("sensitive capability text"),
        ).collect()

        assertEquals(null, snapshot.hardwareSecureAllSupported)
        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.sessionStatus)
        assertTrue(snapshot.errors.any { error ->
            error.stage == WidevineDrmErrorStage.SESSION_CAPABILITY
        })
        assertFalse(snapshot.toString().contains("sensitive capability text"))
        assertTrue(client.sessionClosed)
        assertTrue(client.closed)
    }

    @Test
    fun `empty session id is rejected and never used`() {
        val client = FakeMediaDrmClient(emptySessionId = true)

        val snapshot = probe(client).collect()

        assertEquals(WidevineOperationStatus.FAILURE, snapshot.sessionStatus)
        assertEquals(null, snapshot.actualSessionSecurityLevel)
        assertEquals(WidevineOperationStatus.NOT_ATTEMPTED, snapshot.keyRequestStatus)
        assertFalse(client.sessionCloseAttempted)
        assertTrue(snapshot.errors.any { error ->
            error.stage == WidevineDrmErrorStage.SESSION_OPEN &&
                error.kind == WidevineDrmErrorKind.INVALID_SESSION_ID
        })
        assertTrue(client.closed)
    }

    private fun probe(
        client: FakeMediaDrmClient,
        errorMetadataReader: WidevineDrmErrorMetadataReader? = null,
        hardwareSecureAllSupported: Boolean = true,
        capabilityError: Exception? = null,
    ): WidevineCredentialProbe {
        return WidevineCredentialProbe(
            mediaDrmFactory = object : WidevineMediaDrmFactory {
                override fun isCryptoSchemeSupported(): Boolean = true

                override fun isHardwareSecureAllSupported(): Boolean {
                    capabilityError?.let { throw it }
                    return hardwareSecureAllSupported
                }

                override fun create(): WidevineMediaDrmClient = client
            },
            nativePropertyReader = WidevineNativePropertyReader {
                WidevineNativeSnapshot(
                    available = true,
                    securityLevel = WidevinePropertyRead(
                        WidevinePropertyStatus.AVAILABLE,
                        "L1",
                    ),
                    systemId = WidevinePropertyRead(
                        WidevinePropertyStatus.AVAILABLE,
                        "38497",
                    ),
                    securityLevelStatusCode = 0,
                    systemIdStatusCode = 0,
                )
            },
            errorMetadataReader = errorMetadataReader ?: WidevineDrmErrorMetadataReader {
                WidevineDrmErrorMetadata()
            },
        )
    }

    private class FakeMediaDrmClient(
        private val openError: Throwable? = null,
        private val keyRequestError: Throwable? = null,
        private val propertyError: Throwable? = null,
        private val closeSessionError: Throwable? = null,
        private val securityLevelValue: String = "L1",
        private val systemIdValue: String = "38497",
        private val emptySessionId: Boolean = false,
    ) : WidevineMediaDrmClient {
        var deviceUniqueIdChecked = false
        var keyRequestGenerated = false
        var sessionClosed = false
        var sessionCloseAttempted = false
        var closed = false
        var openedSession: ByteArray? = null

        override fun getPropertyString(name: String): String {
            propertyError?.let { throw it }
            return when (name) {
                "securityLevel" -> securityLevelValue
                "systemId" -> systemIdValue
                else -> error("unexpected property")
            }
        }

        override fun openMaximumSecuritySession(): ByteArray {
            openError?.let { throw it }
            return if (emptySessionId) {
                byteArrayOf()
            } else {
                byteArrayOf(1, 2, 3).also { openedSession = it }
            }
        }

        override fun getSecurityLevel(sessionId: ByteArray): WidevineSessionSecurityLevel {
            return WidevineSessionSecurityLevel.HW_SECURE_ALL
        }

        override fun hasDeviceUniqueId(): Boolean {
            deviceUniqueIdChecked = true
            return true
        }

        override fun generateTestKeyRequest(sessionId: ByteArray) {
            keyRequestGenerated = true
            keyRequestError?.let { throw it }
        }

        override fun closeSession(sessionId: ByteArray) {
            sessionCloseAttempted = true
            closeSessionError?.let { throw it }
            sessionClosed = true
        }

        override fun close() {
            closed = true
        }
    }
}
