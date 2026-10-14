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

import com.eltavine.duckdetector.features.update.domain.MAX_UPDATE_APK_BYTES
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.InetSocketAddress
import java.net.HttpURLConnection
import java.net.URL
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
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
    private val apkRequests = AtomicInteger()
    private val payload = "duck-detector-apk-payload".toByteArray()

    @Before
    fun setUp() {
        downloadDirectory = File.createTempFile("update-downloads", "").apply {
            delete()
            mkdirs()
        }
        server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/apk") { exchange ->
                apkRequests.incrementAndGet()
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
        val apk = apk(size = payload.size.toLong(), sha256 = sha256(payload))
        var lastProgress: UpdateDownloadProgress? = null

        val result = downloader(apk).download(apk, url()) { lastProgress = it }

        val ready = result as UpdateDownloadResult.Ready
        assertEquals(File(downloadDirectory, "${apk.sha256}.apk").absolutePath, ready.apkPath)
        assertEquals(payload.size.toLong(), lastProgress?.bytesRead)
        assertTrue(File(ready.apkPath).isFile)
    }

    @Test
    fun `a mismatched sha256 is rejected and nothing is kept`() = runTest {
        val apk = apk(size = payload.size.toLong(), sha256 = "0".repeat(64))

        val result = downloader(apk).download(apk, url()) {}

        assertEquals(UpdateDownloadResult.Failed, result)
        assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun `a mismatched size is rejected`() = runTest {
        val apk = apk(size = payload.size + 1L, sha256 = sha256(payload))

        assertEquals(UpdateDownloadResult.Failed, downloader(apk).download(apk, url()) {})
    }

    @Test
    fun `chunked overlong bodies stop before exceeding the manifest`() = runTest {
        server.createContext("/chunked") { exchange ->
            exchange.sendResponseHeaders(200, 0)
            exchange.responseBody.use { it.write(ByteArray(1024 * 1024)) }
        }
        val apk = apk(size = 8L, sha256 = sha256(payload))
        val progress = mutableListOf<UpdateDownloadProgress>()
        assertEquals(UpdateDownloadResult.Failed, downloader(apk).download(apk, url("/chunked")) { progress += it })
        assertTrue(progress.all { it.bytesRead <= apk.sizeBytes && it.totalBytes == apk.sizeBytes })
        assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun `untrusted digest and unavailable official metadata fail before the apk request`() = runTest {
        val apk = apk(size = payload.size.toLong(), sha256 = sha256(payload))
        val forged = apk.copy(sha256 = "f".repeat(64))
        assertEquals(UpdateDownloadResult.Failed, downloader(forged, trustedApk = { apk }).download(forged, url()) {})
        assertEquals(UpdateDownloadResult.Failed, downloader(apk, trustedApk = { throw IOException("offline") }).download(apk, url()) {})
        assertEquals(0, apkRequests.get())
        assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun `manifest sizes above the fixed cap never fetch metadata or create files`() = runTest {
        val apk = apk(size = MAX_UPDATE_APK_BYTES + 1, sha256 = sha256(payload))
        var metadataFetched = false
        val downloader = downloader(apk, trustedApk = { metadataFetched = true; apk })
        assertEquals(UpdateDownloadResult.Failed, downloader.download(apk, url()) {})
        assertTrue(!metadataFetched)
        assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun `fast transfers emit only initial and verified final progress`() = runTest {
        val bytes = ByteArray(1024 * 1024)
        server.createContext("/large") { exchange ->
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        val apk = apk(bytes.size.toLong(), sha256(bytes))
        val progress = mutableListOf<UpdateDownloadProgress>()
        val result = downloader(apk, nanoTime = { 0L }).download(apk, url("/large")) { progress += it }
        assertTrue(result is UpdateDownloadResult.Ready)
        assertEquals(listOf(0L, bytes.size.toLong()), progress.map { it.bytesRead })
    }

    @Test
    fun `intermediate progress is bounded by the reporting interval`() = runTest {
        val bytes = ByteArray(1024 * 1024)
        server.createContext("/paced") { exchange ->
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        val apk = apk(bytes.size.toLong(), sha256(bytes))
        var clock = 0L
        val intermediateTimes = mutableListOf<Long>()
        val result = downloader(apk, nanoTime = { clock += 100_000_000L; clock }).download(apk, url("/paced")) {
            if (it.bytesRead in 1 until apk.sizeBytes) intermediateTimes += clock
        }
        assertTrue(result is UpdateDownloadResult.Ready)
        assertTrue(intermediateTimes.isNotEmpty())
        assertTrue(intermediateTimes.zipWithNext().all { (a, b) -> b - a >= 250_000_000L })
    }

    @Test
    fun `partial response status and redirect loops are rejected`() = runTest {
        server.createContext("/partial") { exchange ->
            exchange.sendResponseHeaders(206, payload.size.toLong())
            exchange.responseBody.use { it.write(payload) }
        }
        server.createContext("/loop") { exchange ->
            exchange.responseHeaders.add("Location", "/loop")
            exchange.sendResponseHeaders(302, -1)
            exchange.close()
        }
        val apk = apk(payload.size.toLong(), sha256(payload))
        assertEquals(UpdateDownloadResult.Failed, downloader(apk).download(apk, url("/partial")) {})
        assertEquals(UpdateDownloadResult.Failed, downloader(apk).download(apk, url("/loop")) {})
        assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun `cancellation cleans the partial file and propagates`() = runTest {
        val apk = apk(payload.size.toLong(), sha256(payload))
        try {
            downloader(apk).download(apk, url()) { throw CancellationException("cancelled") }
            throw AssertionError("Expected cancellation")
        } catch (_: CancellationException) {
            assertTrue(downloadDirectory.listFiles().orEmpty().isEmpty())
        }
    }

    @Test
    fun `failed rename cleans the partial file`() = runTest {
        val apk = apk(payload.size.toLong(), sha256(payload))
        val target = File(downloadDirectory, "${apk.sha256}.apk").apply { mkdirs() }
        File(target, "occupied").writeText("keep")
        assertEquals(UpdateDownloadResult.Failed, downloader(apk).download(apk, url()) {})
        assertEquals(listOf(target.name), downloadDirectory.listFiles().orEmpty().map { it.name })
    }

    @Test
    fun `redirects may stay on https but never downgrade to http`() = runTest {
        server.createContext("/redirect") { exchange ->
            exchange.responseHeaders.add("Location", "/apk")
            exchange.sendResponseHeaders(302, -1)
            exchange.close()
        }
        server.createContext("/downgrade") { exchange ->
            exchange.responseHeaders.add("Location", "http://github.com/apk")
            exchange.sendResponseHeaders(302, -1)
            exchange.close()
        }
        val apk = apk(payload.size.toLong(), sha256(payload))
        assertTrue(downloader(apk).download(apk, url("/redirect")) {} is UpdateDownloadResult.Ready)
        assertEquals(UpdateDownloadResult.Failed, downloader(apk).download(apk, url("/downgrade")) {})
    }

    private fun url(path: String = "/apk"): String = "https://github.com$path"

    private fun downloader(
        apk: NightlyUpdateApk,
        trustedApk: () -> NightlyUpdateApk = { apk },
        nanoTime: () -> Long = System::nanoTime,
    ) = HttpUpdateApkDownloader(
        downloadDirectory,
        trustedApk = trustedApk,
        openConnection = { URL("http://127.0.0.1:${server.address.port}${it.path}").openConnection() as HttpURLConnection },
        nanoTime = nanoTime,
    )

    private fun apk(size: Long, sha256: String) = NightlyUpdateApk(
        name = "Duck.Detector-test.apk",
        downloadUrl = url(),
        sizeBytes = size,
        sha256 = sha256,
    )

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
