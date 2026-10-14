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

import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.InetSocketAddress
import java.security.MessageDigest
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class HttpUpdateApkDownloaderTest {

    private lateinit var server: HttpServer
    private lateinit var downloadDirectory: File
    private val payload = "duck-detector-apk-payload".toByteArray()

    @Before
    fun setUp() {
        downloadDirectory = File.createTempFile("update-downloads", "").apply {
            delete()
            mkdirs()
        }
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/apk") { exchange ->
                exchange.sendResponseHeaders(200, payload.size.toLong())
                exchange.responseBody.use { it.write(payload) }
            }
            start()
        }
    }

    @After
    fun tearDown() {
        server.stop(0)
        downloadDirectory.deleteRecursively()
    }

    @Test
    fun `a matching size and sha256 produces a ready apk`() = runTest {
        val downloader = HttpUpdateApkDownloader(downloadDirectory)
        val apk = apk(size = payload.size.toLong(), sha256 = sha256(payload))
        var lastProgress: UpdateDownloadProgress? = null

        val result = downloader.download(apk, url()) { lastProgress = it }

        val ready = result as UpdateDownloadResult.Ready
        assertEquals(File(downloadDirectory, apk.name).absolutePath, ready.apkPath)
        assertEquals(payload.size.toLong(), lastProgress?.bytesRead)
        assertTrue(File(ready.apkPath).isFile)
    }

    @Test
    fun `a mismatched sha256 is rejected and nothing is kept`() = runTest {
        val downloader = HttpUpdateApkDownloader(downloadDirectory)
        val apk = apk(size = payload.size.toLong(), sha256 = "0".repeat(64))

        val result = downloader.download(apk, url()) {}

        assertEquals(UpdateDownloadResult.Failed, result)
        assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun `a mismatched size is rejected`() = runTest {
        val downloader = HttpUpdateApkDownloader(downloadDirectory)
        val apk = apk(size = payload.size + 1L, sha256 = sha256(payload))

        assertEquals(UpdateDownloadResult.Failed, downloader.download(apk, url()) {})
    }

    private fun url(): String = "http://127.0.0.1:${server.address.port}/apk"

    private fun apk(size: Long, sha256: String) = NightlyUpdateApk(
        name = "Duck.Detector-test.apk",
        downloadUrl = url(),
        sizeBytes = size,
        sha256 = sha256,
    )

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
