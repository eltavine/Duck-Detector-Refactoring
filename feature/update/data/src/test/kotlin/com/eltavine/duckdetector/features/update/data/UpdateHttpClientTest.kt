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

package com.eltavine.duckdetector.features.update.data

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import java.net.HttpURLConnection
import java.net.URL
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UpdateHttpClientTest {

    @Test
    fun `retries a transient release asset 404`() {
        val attempts = AtomicInteger()
        withServer(
            handler = HttpHandler { exchange ->
                if (attempts.incrementAndGet() == 1) {
                    exchange.respond(statusCode = 404)
                } else {
                    exchange.respond(statusCode = 200, body = "{\"ok\":true}")
                }
            },
        ) { url ->
            val body = HttpUrlConnectionUpdateClient(openConnection = { URL(url).openConnection() as HttpURLConnection }).get("https://github.com/update.json", "application/json")

            assertEquals("{\"ok\":true}", body)
            assertEquals(2, attempts.get())
        }
    }

    @Test
    fun `does not retry a permanent authorization failure`() {
        val attempts = AtomicInteger()
        withServer(
            handler = HttpHandler { exchange ->
                attempts.incrementAndGet()
                exchange.respond(statusCode = 403)
            },
        ) { url ->
            assertThrows(UpdateHttpException::class.java) {
                HttpUrlConnectionUpdateClient(openConnection = { URL(url).openConnection() as HttpURLConnection }).get("https://github.com/update.json", "application/json")
            }
            assertEquals(1, attempts.get())
        }
    }

    private fun withServer(
        handler: HttpHandler,
        block: (String) -> Unit,
    ) {
        val server = HttpServer.create(
            InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
            0,
        )
        server.createContext("/update.json", handler)
        server.start()
        try {
            block("http://127.0.0.1:${server.address.port}/update.json")
        } finally {
            server.stop(0)
        }
    }
}

private fun HttpExchange.respond(statusCode: Int, body: String = "") {
    val bytes = body.toByteArray(Charsets.UTF_8)
    try {
        sendResponseHeaders(statusCode, if (bytes.isEmpty()) -1 else bytes.size.toLong())
        if (bytes.isNotEmpty()) {
            responseBody.use { it.write(bytes) }
        }
    } finally {
        close()
    }
}
