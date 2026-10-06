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
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProtocolSnapshot
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Identifies an ADB network listener by speaking only the first ADB protocol round trip.
 *
 * The probe sends A_CNXN and reads exactly one response. Legacy ADB answers with A_AUTH/TOKEN or
 * A_CNXN; the Wireless Debugging secure-connect transport answers with A_STLS before the TLS
 * handshake. The probe never sends an AUTH signature, RSA public key, A_STLS reply, OPEN, TLS
 * handshake bytes, or any service command.
 *
 * Android 10 tag android-10.0.0_r47, system/core commit
 * 1dea9a052b7f214c10a77d5ed6ffd3602722a817:
 * - A_CNXN/A_AUTH and protocol versions: adb/adb.h lines 34-54
 *   https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb.h#34
 * - six-word little-endian message header: adb/types.h lines 125-132
 *   https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/types.h#125
 * - canonical A_CNXN construction: adb/adb.cpp lines 212-233
 *   https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb.cpp#212
 * - authenticated devices answer with A_CNXN, otherwise send_auth_request(): lines 294-307
 *   https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb.cpp#294
 * - AUTH TOKEN=1, SIGNATURE=2, RSAPUBLICKEY=3: adb/adb_auth.h lines 27-32
 *   https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb_auth.h#27
 * - adbd emits the AUTH token at daemon/auth.cpp lines 262-276
 *   https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/auth.cpp#262
 *
 * Android 16 tag android-16.0.0_r3, packages/modules/adb commit
 * cf10d3798f0847f89820381b541aedfd27a30375:
 * - A_STLS and its version are adb.h lines 49 and 61-62:
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.h#49
 * - TlsServer accepts the secure-connect socket and registers it with use_tls=true at
 *   daemon/adb_wifi.cpp lines 127-142:
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/adb_wifi.cpp#127
 * - register_socket_transport stores that flag in atransport::use_tls at transport.cpp
 *   lines 1510-1520:
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/transport.cpp#1510
 * - send_tls_request() constructs A_STLS/A_STLS_VERSION with no payload at adb.cpp lines 318-324:
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#318
 * - after the initial CNXN, use_tls selects send_tls_request(t) at adb.cpp lines 420-430:
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#420
 * - AUTH token size is fixed at 20 bytes in adb.h line 103
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.h#103
 * - send_packet sets magic/checksum at transport.cpp lines 565-576
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/transport.cpp#565
 * - header validation checks magic and payload length at lines 1705-1718
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/transport.cpp#1705
 * - RSAPUBLICKEY is the branch that calls adbd_auth_confirm_key(): adb.cpp lines 462-490
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#462
 * - adbd_auth_confirm_key() is the user-prompt path: daemon/auth.cpp lines 311-318
 *   https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/auth.cpp#311
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
                detail = "Legacy ADB endpoint was not valid.",
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
                state = AdbProbeState.NOT_OBSERVED,
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
