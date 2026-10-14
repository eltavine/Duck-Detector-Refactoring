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
import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/**
 * APK transport may use acceleration, but its digest and size must match an independent HTTPS
 * fetch of the official manifest. Failure to obtain that baseline never falls back to proxy trust.
 */
internal class HttpUpdateApkDownloader(
    private val downloadDirectory: File,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val trustedApk: () -> NightlyUpdateApk = {
        UpdateManifestParser().parse(
            HttpUrlConnectionUpdateClient().get(UpdateRepository.MANIFEST_URL, "application/json"),
        ).apk
    },
    private val openConnection: (URL) -> HttpURLConnection = {
        it.openConnection() as HttpURLConnection
    },
    private val nanoTime: () -> Long = System::nanoTime,
) : UpdateApkDownloader {

    override suspend fun download(
        apk: NightlyUpdateApk,
        downloadUrl: String,
        onProgress: (UpdateDownloadProgress) -> Unit,
    ): UpdateDownloadResult = withContext(ioDispatcher) {
        var partial: File? = null
        try {
            require(apk.sizeBytes in 1..MAX_UPDATE_APK_BYTES)
            require(Regex("[0-9a-fA-F]{64}").matches(apk.sha256))
            coroutineContext.ensureActive()
            if (trustedApk() != apk) {
                return@withContext UpdateDownloadResult.Failed
            }
            coroutineContext.ensureActive()
            check(downloadDirectory.isDirectory || downloadDirectory.mkdirs())
            val pending = File.createTempFile("update-", ".part", downloadDirectory)
            partial = pending
            streamToFile(downloadUrl, pending, apk, onProgress)
            coroutineContext.ensureActive()
            // Content addressing prevents different releases with the same asset name colliding.
            val target = File(downloadDirectory, "${apk.sha256.lowercase()}.apk")
            if (!pending.renameTo(target)) {
                return@withContext UpdateDownloadResult.Failed
            }
            onProgress(UpdateDownloadProgress(apk.sizeBytes, apk.sizeBytes))
            UpdateDownloadResult.Ready(target.absolutePath)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            UpdateDownloadResult.Failed
        } finally {
            partial?.delete()
        }
    }

    private suspend fun streamToFile(
        url: String,
        file: File,
        apk: NightlyUpdateApk,
        onProgress: (UpdateDownloadProgress) -> Unit,
    ) {
        val context = coroutineContext
        val connection = openUpdateConnection(
            initialUrl = URL(url),
            accept = "application/octet-stream",
            connectTimeoutMillis = CONNECT_TIMEOUT_MILLIS,
            readTimeoutMillis = READ_TIMEOUT_MILLIS,
            openConnection = openConnection,
            checkActive = { context.ensureActive() },
        )
        try {
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                throw IOException("APK download failed with HTTP ${connection.responseCode}")
            }
            val length = connection.contentLengthLong
            if (length >= 0L && length != apk.sizeBytes) {
                throw IOException("APK Content-Length differs from the manifest.")
            }
            val digest = MessageDigest.getInstance("SHA-256")
            var bytesRead = 0L
            var lastProgressTime = nanoTime()
            onProgress(UpdateDownloadProgress(0L, apk.sizeBytes))
            connection.inputStream.use { input ->
                file.outputStream().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        coroutineContext.ensureActive()
                        val count = input.read(buffer)
                        if (count < 0) break
                        // Check before writing, even for chunked bodies and dishonest headers.
                        if (count.toLong() > apk.sizeBytes - bytesRead) {
                            throw IOException("APK exceeds the manifest size.")
                        }
                        output.write(buffer, 0, count)
                        digest.update(buffer, 0, count)
                        bytesRead += count
                        val now = nanoTime()
                        if (bytesRead < apk.sizeBytes && now - lastProgressTime >= PROGRESS_INTERVAL_NANOS) {
                            onProgress(UpdateDownloadProgress(bytesRead, apk.sizeBytes))
                            lastProgressTime = now
                        }
                    }
                }
            }
            val actualHash = digest.digest().joinToString("") { "%02x".format(it) }
            if (bytesRead != apk.sizeBytes || !actualHash.equals(apk.sha256, ignoreCase = true)) {
                throw IOException("APK size or SHA-256 verification failed.")
            }
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        private const val CONNECT_TIMEOUT_MILLIS = 10_000
        private const val READ_TIMEOUT_MILLIS = 30_000
        private const val PROGRESS_INTERVAL_NANOS = 250_000_000L
    }
}
