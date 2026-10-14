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

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

internal class UpdateHttpException(
    val statusCode: Int,
) : IOException("GitHub update request failed with HTTP $statusCode")

internal fun interface UpdateHttpClient {
    fun get(url: String, accept: String): String
}

internal class HttpUrlConnectionUpdateClient(
    private val openConnection: (URL) -> HttpURLConnection = { it.openConnection() as HttpURLConnection },
) : UpdateHttpClient {

    override fun get(url: String, accept: String): String {
        var lastFailure: IOException? = null
        repeat(MAX_ATTEMPTS) { attempt ->
            try {
                return executeGet(url, accept)
            } catch (failure: IOException) {
                lastFailure = failure
                if (attempt == MAX_ATTEMPTS - 1 || !failure.isRetryable()) {
                    throw failure
                }
                waitBeforeRetry(attempt)
            }
        }
        throw checkNotNull(lastFailure)
    }

    private fun executeGet(url: String, accept: String): String {
        val connection = openUpdateConnection(
            initialUrl = URL(url),
            accept = accept,
            connectTimeoutMillis = CONNECT_TIMEOUT_MILLIS,
            readTimeoutMillis = READ_TIMEOUT_MILLIS,
            openConnection = openConnection,
        )
        return try {
            val statusCode = connection.responseCode
            val stream = if (statusCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            val body = stream?.use { it.readUtf8(MAX_RESPONSE_BYTES) }.orEmpty()
            if (statusCode !in 200..299) {
                throw UpdateHttpException(statusCode)
            }
            body
        } finally {
            connection.disconnect()
        }
    }

    private fun IOException.isRetryable(): Boolean {
        return this !is UpdateResponseTooLargeException &&
            (this !is UpdateHttpException || statusCode in RETRYABLE_STATUS_CODES || statusCode >= 500)
    }

    private fun waitBeforeRetry(attempt: Int) {
        try {
            Thread.sleep(RETRY_DELAYS_MILLIS[attempt])
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw IOException("GitHub update request retry was interrupted.", interrupted)
        }
    }

    private companion object {
        private const val CONNECT_TIMEOUT_MILLIS = 5_000
        private const val READ_TIMEOUT_MILLIS = 10_000
        private const val MAX_ATTEMPTS = 3
        private const val MAX_RESPONSE_BYTES = 4 * 1024 * 1024
        private val RETRY_DELAYS_MILLIS = longArrayOf(250L, 750L)
        private val RETRYABLE_STATUS_CODES = setOf(404, 408, 425, 429)
    }
}

private class UpdateResponseTooLargeException(limitBytes: Int) :
    IOException("GitHub update response exceeds $limitBytes bytes.")

private fun InputStream.readUtf8(limitBytes: Int): String {
    val output = ByteArrayOutputStream(minOf(limitBytes, DEFAULT_BUFFER_SIZE))
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    var totalBytes = 0
    while (true) {
        val count = read(buffer)
        if (count < 0) {
            break
        }
        totalBytes += count
        if (totalBytes > limitBytes) {
            throw UpdateResponseTooLargeException(limitBytes)
        }
        output.write(buffer, 0, count)
    }
    return output.toString(Charsets.UTF_8.name())
}
