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

import android.system.ErrnoException
import android.system.OsConstants
import com.eltavine.duckdetector.features.adbruntime.domain.AdbMdnsServiceKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolResponseKind
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolSnapshot
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Identifies an ADB listener by the one packet it answers to an initial A_CNXN.
 *
 * Legacy adbd answers A_AUTH/ADB_AUTH_TOKEN, or A_CNXN when it requires no authentication; the
 * Wireless debugging secure-connect transport answers A_STLS before any TLS. The probe reads that
 * packet and closes. It never sends an AUTH signature or RSA public key, the packets that reach
 * adbd's authorization prompt, nor an A_STLS reply, TLS bytes, A_OPEN or a service command.
 * EVIDENCE.md, "ADB wire protocol identity", traces every constant and branch to AOSP.
 */
internal class AdbProtocolProbe(
    private val connectTimeoutMs: Int = CONNECT_TIMEOUT_MS,
    private val readTimeoutMs: Int = READ_TIMEOUT_MS,
) {
    fun collect(
        address: String,
        port: Int,
        serviceKind: AdbMdnsServiceKind,
    ): AdbProtocolSnapshot {
        if (address.isBlank() || port !in 1..65535) {
            return AdbProtocolSnapshot(
                state = AdbProbeState.UNAVAILABLE,
                detail = "The advertised ADB endpoint was not valid.",
            )
        }

        return try {
            Socket().use { socket ->
                socket.soTimeout = readTimeoutMs
                socket.connect(InetSocketAddress(address, port), connectTimeoutMs)
                socket.getOutputStream().apply {
                    write(buildConnectPacket())
                    flush()
                }
                readResponse(socket.getInputStream(), serviceKind)
            }
        } catch (_: SocketTimeoutException) {
            AdbProtocolSnapshot(
                state = AdbProbeState.NOT_OBSERVED,
                detail = "The local listener did not answer the ADB handshake before timeout.",
            )
        } catch (_: EOFException) {
            AdbProtocolSnapshot(
                state = AdbProbeState.NOT_OBSERVED,
                detail = "The local listener closed before returning an ADB packet.",
            )
        } catch (failure: IOException) {
            AdbProtocolSnapshot(
                state = failure.probeState(),
                detail = failure.message ?: "The local listener did not complete an ADB handshake.",
            )
        } catch (failure: RuntimeException) {
            AdbProtocolSnapshot(
                state = AdbProbeState.UNAVAILABLE,
                detail = failure.message ?: "ADB protocol probe unavailable.",
            )
        }
    }

    private fun buildConnectPacket(): ByteArray {
        val payload = HOST_BANNER.toByteArray(StandardCharsets.UTF_8)
        val header = ByteBuffer.allocate(HEADER_SIZE + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(A_CNXN)
            .putInt(A_VERSION)
            .putInt(MAX_PAYLOAD_V1)
            .putInt(payload.size)
            .putInt(checksum(payload))
            .putInt(A_CNXN xor -1)
        header.put(payload)
        return header.array()
    }

    private fun readResponse(
        input: InputStream,
        serviceKind: AdbMdnsServiceKind,
    ): AdbProtocolSnapshot {
        val rawHeader = readExactly(input, HEADER_SIZE)
        val header = ByteBuffer.wrap(rawHeader).order(ByteOrder.LITTLE_ENDIAN)
        val command = header.int
        val arg0 = header.int
        val arg1 = header.int
        val dataLength = header.int
        val dataCheck = header.int
        val magic = header.int

        if (magic != (command xor -1) || dataLength !in 0..MAX_INITIAL_RESPONSE_PAYLOAD) {
            return invalid("The listener returned an invalid ADB header.")
        }

        val payload = readExactly(input, dataLength)
        if (dataCheck != 0 && dataCheck != checksum(payload)) {
            return invalid("The listener returned an ADB packet with an invalid checksum.")
        }

        return when {
            serviceKind == AdbMdnsServiceKind.LEGACY_TCP &&
                command == A_AUTH &&
                arg0 == ADB_AUTH_TOKEN &&
                arg1 == 0 &&
                payload.size == TOKEN_SIZE ->
                AdbProtocolSnapshot(
                    state = AdbProbeState.OBSERVED,
                    responseKind = AdbProtocolResponseKind.AUTH_TOKEN,
                    detail = "The local listener answered A_CNXN with an ADB AUTH token.",
                )

            serviceKind == AdbMdnsServiceKind.LEGACY_TCP &&
                command == A_CNXN &&
                arg0 >= A_VERSION_MIN &&
                arg1 in 1..MAX_PAYLOAD &&
                payload.containsConnectionBanner() ->
                AdbProtocolSnapshot(
                    state = AdbProbeState.OBSERVED,
                    responseKind = AdbProtocolResponseKind.CONNECT,
                    detail = "The local listener answered with a valid ADB CNXN banner.",
                )

            serviceKind == AdbMdnsServiceKind.TLS_CONNECT &&
                command == A_STLS &&
                arg0 == A_STLS_VERSION &&
                arg1 == 0 &&
                payload.isEmpty() ->
                AdbProtocolSnapshot(
                    state = AdbProbeState.OBSERVED,
                    responseKind = AdbProtocolResponseKind.START_TLS,
                    detail = "The local listener answered A_CNXN with the ADB START_TLS packet.",
                )

            else -> invalid("The local listener did not return the expected ADB first packet for this service type.")
        }
    }

    private fun invalid(detail: String) = AdbProtocolSnapshot(
        state = AdbProbeState.NOT_OBSERVED,
        detail = detail,
    )

    private fun readExactly(input: InputStream, length: Int): ByteArray {
        if (length == 0) {
            return ByteArray(0)
        }
        val result = ByteArray(length)
        var offset = 0
        while (offset < result.size) {
            val count = input.read(result, offset, result.size - offset)
            if (count < 0) {
                throw EOFException()
            }
            offset += count
        }
        return result
    }

    private fun checksum(bytes: ByteArray): Int =
        bytes.fold(0) { sum, byte -> sum + (byte.toInt() and 0xff) }

    private fun ByteArray.containsConnectionBanner(): Boolean {
        if (isEmpty()) {
            return false
        }
        val banner = String(this, StandardCharsets.UTF_8)
        return banner.contains("::") &&
            banner.substringBefore("::").all { character ->
                character.isLetterOrDigit() || character == '_' || character == '-'
            }
    }

    private companion object {
        const val A_CNXN = 0x4e584e43
        const val A_AUTH = 0x48545541
        const val A_STLS = 0x534c5453
        const val ADB_AUTH_TOKEN = 1
        const val A_STLS_VERSION = 0x01000000
        const val A_VERSION_MIN = 0x01000000
        const val A_VERSION = 0x01000001
        const val MAX_PAYLOAD_V1 = 4 * 1024
        const val MAX_PAYLOAD = 1024 * 1024
        const val MAX_INITIAL_RESPONSE_PAYLOAD = MAX_PAYLOAD_V1
        const val TOKEN_SIZE = 20
        const val HEADER_SIZE = 6 * Int.SIZE_BYTES
        const val HOST_BANNER = "host::features="
        const val CONNECT_TIMEOUT_MS = 500
        const val READ_TIMEOUT_MS = 750
    }
}

/*
 * A refused, reset or silent listener is an answer about the endpoint; a permission or routing
 * error is not. libcore keeps the errno as an ErrnoException cause. Without INTERNET, netd's BPF
 * socket-create filter fails socket() with EPERM, as does a network policy that blocks the
 * connection, and an SELinux denial fails with EACCES (EVIDENCE.md, "ADB wire protocol identity").
 */
private fun IOException.probeState(): AdbProbeState {
    if (this is NoRouteToHostException) {
        return AdbProbeState.UNAVAILABLE
    }
    val errno = generateSequence<Throwable>(this) { it.cause }
        .filterIsInstance<ErrnoException>()
        .firstOrNull()
        ?.errno
        ?: return AdbProbeState.NOT_OBSERVED
    return when (errno) {
        OsConstants.EACCES, OsConstants.EPERM -> AdbProbeState.PERMISSION_REQUIRED
        OsConstants.ENETUNREACH, OsConstants.EHOSTUNREACH -> AdbProbeState.UNAVAILABLE
        else -> AdbProbeState.NOT_OBSERVED
    }
}
