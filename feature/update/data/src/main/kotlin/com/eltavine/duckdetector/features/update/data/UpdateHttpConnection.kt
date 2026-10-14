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

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Release assets redirect to GitHub storage. Each hop must keep authenticated HTTPS transport. */
internal fun openUpdateConnection(
    initialUrl: URL,
    accept: String,
    connectTimeoutMillis: Int,
    readTimeoutMillis: Int,
    openConnection: (URL) -> HttpURLConnection,
    checkActive: () -> Unit = {},
): HttpURLConnection {
    var url = initialUrl
    repeat(6) { redirects ->
        checkActive()
        if (url.protocol != "https" || url.userInfo != null) {
            throw IOException("Update transport requires HTTPS without URL credentials.")
        }
        val connection = openConnection(url)
        var retained = false
        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = connectTimeoutMillis
            connection.readTimeout = readTimeoutMillis
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept", accept)
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("Cache-Control", "no-cache, no-store")
            connection.setRequestProperty("Pragma", "no-cache")
            connection.setRequestProperty("User-Agent", "Duck-Detector-Android")
            if (url.host.equals("api.github.com", ignoreCase = true)) {
                connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            }
            if (connection.responseCode !in setOf(301, 302, 303, 307, 308)) {
                retained = true
                return connection
            }
            if (redirects == 5) throw IOException("Too many update redirects.")
            val location = connection.getHeaderField("Location")
                ?: throw IOException("Update redirect has no Location.")
            url = URL(url, location)
        } finally {
            if (!retained) connection.disconnect()
        }
    }
    throw IOException("Too many update redirects.")
}
