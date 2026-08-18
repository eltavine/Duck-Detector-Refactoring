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

        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.sessionStatus)
        assertEquals(WidevineSessionSecurityLevel.HW_SECURE_ALL, snapshot.actualSessionSecurityLevel)
        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.credentialStatus)
        assertEquals(true, snapshot.credentialAvailable)
        assertEquals(WidevineOperationStatus.SUCCESS, snapshot.keyRequestStatus)
        assertTrue(client.deviceUniqueIdChecked)
        assertTrue(client.keyRequestGenerated)
        assertTrue(client.sessionClosed)
        assertTrue(client.closed)
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
    fun `unsupported scheme skips Java and native collection`() {
        var nativeRead = false
        val probe = WidevineCredentialProbe(
            mediaDrmFactory = object : WidevineMediaDrmFactory {
                override fun isCryptoSchemeSupported(): Boolean = false

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

    private fun probe(client: FakeMediaDrmClient): WidevineCredentialProbe {
        return WidevineCredentialProbe(
            mediaDrmFactory = object : WidevineMediaDrmFactory {
                override fun isCryptoSchemeSupported(): Boolean = true

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
        )
    }

    private class FakeMediaDrmClient(
        private val openError: Throwable? = null,
        private val keyRequestError: Throwable? = null,
        private val propertyError: Throwable? = null,
    ) : WidevineMediaDrmClient {
        var deviceUniqueIdChecked = false
        var keyRequestGenerated = false
        var sessionClosed = false
        var closed = false

        override fun getPropertyString(name: String): String {
            propertyError?.let { throw it }
            return when (name) {
                "securityLevel" -> "L1"
                "systemId" -> "38497"
                else -> error("unexpected property")
            }
        }

        override fun openHardwareSecureAllSession(): ByteArray {
            openError?.let { throw it }
            return byteArrayOf(1, 2, 3)
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
            sessionClosed = true
        }

        override fun close() {
            closed = true
        }
    }
}
