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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets

class SceneLoopbackProbe(
    private val transport: Transport = SocketTransport(),
) {

    fun probe(): SceneLoopbackProbeResult {
        val httpGet = transport.exchange(
            port = HTTP_PORT,
            payload = HTTP_GET_PAYLOAD,
        )
        val invalidPayload = transport.exchange(
            port = HTTP_PORT,
            payload = JSON_PING_PAYLOAD,
        )
        val sideChannel =
            if (matchesHttpStatus(httpGet, 404) && matchesHttpStatus(invalidPayload, 400)) {
                transport.exchange(
                    port = SIDECAR_PORT,
                    payload = JSON_PING_PAYLOAD,
                )
            } else {
                ProbeExchange.unavailable()
            }
        return evaluate(httpGet, invalidPayload, sideChannel)
    }

    internal fun evaluate(
        httpGet: ProbeExchange,
        invalidPayload: ProbeExchange,
        sideChannel: ProbeExchange,
    ): SceneLoopbackProbeResult {
        val get404Matched = matchesHttpStatus(httpGet, 404)
        val invalid400Matched = matchesHttpStatus(invalidPayload, 400)
        if (!get404Matched || !invalid400Matched) {
            return SceneLoopbackProbeResult(
                detected = false,
                get404Matched = get404Matched,
                invalid400Matched = invalid400Matched,
                sideChannelClosed = false,
            )
        }

        val details = mutableListOf(
            "127.0.0.1:$HTTP_PORT GET->404",
            "127.0.0.1:$HTTP_PORT invalid payload->400",
        )
        val sideChannelClosed =
            sideChannel.connected && sideChannel.firstLine == null && !sideChannel.timedOut
        if (sideChannelClosed) {
            details += "127.0.0.1:$SIDECAR_PORT invalid payload closed immediately"
        }

        return SceneLoopbackProbeResult(
            detected = true,
            get404Matched = true,
            invalid400Matched = true,
            sideChannelClosed = sideChannelClosed,
            detail = details.joinToString("; "),
        )
    }

    private fun matchesHttpStatus(
        result: ProbeExchange,
        expectedStatus: Int,
    ): Boolean {
        val firstLine = result.firstLine ?: return false
        return HTTP_STATUS_PATTERN.format(expectedStatus).toRegex().matches(firstLine)
    }

    interface Transport {
        fun exchange(
            port: Int,
            payload: ByteArray,
        ): ProbeExchange
    }

    class SocketTransport : Transport {
        override fun exchange(
            port: Int,
            payload: ByteArray,
        ): ProbeExchange {
            return try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(LOOPBACK_HOST, port), CONNECT_TIMEOUT_MS)
                    socket.soTimeout = READ_TIMEOUT_MS
                    socket.getOutputStream().apply {
                        write(payload)
                        flush()
                    }
                    socket.shutdownOutput()
                    val firstLine = try {
                        readFirstLine(socket)
                    } catch (_: SocketTimeoutException) {
                        return ProbeExchange(
                            connected = true,
                            timedOut = true,
                        )
                    }
                    ProbeExchange(
                        connected = true,
                        firstLine = firstLine?.trim()?.takeIf { it.isNotEmpty() },
                    )
                }
            } catch (_: SocketTimeoutException) {
                ProbeExchange(
                    connected = false,
                    timedOut = true,
                )
            } catch (_: Exception) {
                ProbeExchange.unavailable()
            }
        }

        private fun readFirstLine(socket: Socket): String? {
            return BufferedReader(
                InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8),
            ).use { reader ->
                reader.readLine()
            }
        }
    }

    data class ProbeExchange(
        val connected: Boolean,
        val firstLine: String? = null,
        val timedOut: Boolean = false,
    ) {
        companion object {
            fun unavailable(): ProbeExchange = ProbeExchange(connected = false)
        }
    }

    data class SceneLoopbackProbeResult(
        val detected: Boolean,
        val get404Matched: Boolean,
        val invalid400Matched: Boolean,
        val sideChannelClosed: Boolean,
        val detail: String? = null,
    )

    private companion object {
        private const val LOOPBACK_HOST = "127.0.0.1"
        private const val HTTP_PORT = 8765
        private const val SIDECAR_PORT = 8788
        private const val CONNECT_TIMEOUT_MS = 350
        private const val READ_TIMEOUT_MS = 350
        private const val HTTP_STATUS_PATTERN = "^HTTP/\\d(?:\\.\\d)?\\s+%d(?:\\s+.*)?$"

        private val HTTP_GET_PAYLOAD = (
                "GET / HTTP/1.1\r\n" +
                        "Host: 127.0.0.1\r\n" +
                        "Connection: close\r\n\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)

        private val JSON_PING_PAYLOAD =
            "{\"action\":\"ping\"}\n".toByteArray(StandardCharsets.US_ASCII)
    }
}
