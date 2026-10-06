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

package com.eltavine.duckdetector.features.adbruntime.data.repository

import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolResponseKind
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbProtocolProbeTest {
    @Test
    fun authTokenConfirmsAdbWithoutSendingAuthenticationResponse() {
        withServer(AdbMdnsServiceKind.LEGACY_TCP) { input, output ->
            assertCanonicalConnect(readPacket(input))
            val token = ByteArray(20) { index -> (index + 1).toByte() }
            output.write(packet(A_AUTH, ADB_AUTH_TOKEN, 0, token))
            output.flush()
            assertEquals(-1, input.read())
        }.also { snapshot ->
            assertTrue(snapshot.confirmed)
            assertEquals(AdbProbeState.OBSERVED, snapshot.state)
            assertEquals(AdbProtocolResponseKind.AUTH_TOKEN, snapshot.responseKind)
        }
    }

    @Test
    fun connectBannerConfirmsAdb() {
        withServer(AdbMdnsServiceKind.LEGACY_TCP) { input, output ->
            assertCanonicalConnect(readPacket(input))
            output.write(
                packet(
                    A_CNXN,
                    A_VERSION,
                    MAX_PAYLOAD_V1,
                    "device::features=shell_v2".toByteArray(StandardCharsets.UTF_8),
                ),
            )
            output.flush()
        }.also { snapshot ->
            assertTrue(snapshot.confirmed)
            assertEquals(AdbProtocolResponseKind.CONNECT, snapshot.responseKind)
        }
    }

    @Test
    fun invalidMagicDoesNotConfirmAdb() {
        withServer(AdbMdnsServiceKind.LEGACY_TCP) { input, output ->
            assertCanonicalConnect(readPacket(input))
            val response = packet(A_AUTH, ADB_AUTH_TOKEN, 0, ByteArray(20))
            response[20] = 0
            response[21] = 0
            response[22] = 0
            response[23] = 0
            output.write(response)
            output.flush()
        }.also { snapshot ->
            assertFalse(snapshot.confirmed)
            assertEquals(AdbProbeState.NOT_OBSERVED, snapshot.state)
        }
    }

    @Test
    fun startTlsConfirmsWirelessAdbSecureConnect() {
        withServer(AdbMdnsServiceKind.TLS_CONNECT) { input, output ->
            assertCanonicalConnect(readPacket(input))
            output.write(packet(A_STLS, A_STLS_VERSION, 0, ByteArray(0)))
            output.flush()
            assertEquals(-1, input.read())
        }.also { snapshot ->
            assertTrue(snapshot.confirmed)
            assertEquals(AdbProbeState.OBSERVED, snapshot.state)
            assertEquals(AdbProtocolResponseKind.START_TLS, snapshot.responseKind)
        }
    }

    @Test
    fun authTokenDoesNotImpersonateWirelessAdbSecureConnect() {
        withServer(AdbMdnsServiceKind.TLS_CONNECT) { input, output ->
            assertCanonicalConnect(readPacket(input))
            output.write(packet(A_AUTH, ADB_AUTH_TOKEN, 0, ByteArray(20)))
            output.flush()
        }.also { snapshot ->
            assertFalse(snapshot.confirmed)
            assertEquals(AdbProbeState.NOT_OBSERVED, snapshot.state)
        }
    }

    private fun withServer(
        serviceKind: AdbMdnsServiceKind,
        responder: (InputStream, java.io.OutputStream) -> Unit,
    ) = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
        val executor = Executors.newSingleThreadExecutor()
        try {
            val peer = executor.submit {
                server.accept().use { socket ->
                    socket.soTimeout = 1_000
                    responder(socket.getInputStream(), socket.getOutputStream())
                }
            }
            val snapshot = AdbProtocolProbe(
                connectTimeoutMs = 1_000,
                readTimeoutMs = 1_000,
            ).collect(
                address = server.inetAddress.hostAddress ?: "127.0.0.1",
                port = server.localPort,
                serviceKind = serviceKind,
            )
            peer.get(2, TimeUnit.SECONDS)
            snapshot
        } finally {
            executor.shutdownNow()
        }
    }

    private fun assertCanonicalConnect(packet: WirePacket) {
        assertEquals(A_CNXN, packet.command)
        assertEquals(A_VERSION, packet.arg0)
        assertEquals(MAX_PAYLOAD_V1, packet.arg1)
        assertEquals(packet.command xor -1, packet.magic)
        assertEquals(checksum(packet.payload), packet.dataCheck)
        assertEquals("host::features=", String(packet.payload, StandardCharsets.UTF_8))
    }

    private fun readPacket(input: InputStream): WirePacket {
        val header = ByteBuffer.wrap(readExactly(input, HEADER_SIZE)).order(ByteOrder.LITTLE_ENDIAN)
        val command = header.int
        val arg0 = header.int
        val arg1 = header.int
        val dataLength = header.int
        val dataCheck = header.int
        val magic = header.int
        return WirePacket(
            command = command,
            arg0 = arg0,
            arg1 = arg1,
            dataCheck = dataCheck,
            magic = magic,
            payload = readExactly(input, dataLength),
        )
    }

    private fun packet(command: Int, arg0: Int, arg1: Int, payload: ByteArray): ByteArray =
        ByteBuffer.allocate(HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(command)
            .putInt(arg0)
            .putInt(arg1)
            .putInt(payload.size)
            .putInt(0)
            .putInt(command xor -1)
            .put(payload)
            .array()

    private fun readExactly(input: InputStream, length: Int): ByteArray {
        val result = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val count = input.read(result, offset, length - offset)
            check(count >= 0)
            offset += count
        }
        return result
    }

    private fun checksum(bytes: ByteArray): Int =
        bytes.fold(0) { sum, byte -> sum + (byte.toInt() and 0xff) }

    private data class WirePacket(
        val command: Int,
        val arg0: Int,
        val arg1: Int,
        val dataCheck: Int,
        val magic: Int,
        val payload: ByteArray,
    )

    private companion object {
        const val A_CNXN = 0x4e584e43
        const val A_AUTH = 0x48545541
        const val A_STLS = 0x534c5453
        const val ADB_AUTH_TOKEN = 1
        const val A_STLS_VERSION = 0x01000000
        const val A_VERSION = 0x01000001
        const val MAX_PAYLOAD_V1 = 4 * 1024
        const val HEADER_SIZE = 24
    }
}
