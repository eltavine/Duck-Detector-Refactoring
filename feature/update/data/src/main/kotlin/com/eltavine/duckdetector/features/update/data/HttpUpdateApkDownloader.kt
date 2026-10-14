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
import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import java.io.File
import java.io.IOException
import java.io.InputStream
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
 * Streams the Nightly APK to [downloadDirectory] over the same route the check used, then verifies
 * the manifest's size and SHA-256 before reporting it as [UpdateDownloadResult.Ready].
 *
 * The file is written to a `.part` sibling and only renamed once both checks pass, so a partial or
 * tampered download is never left where the installer could pick it up.
 */
internal class HttpUpdateApkDownloader(
    private val downloadDirectory: File,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : UpdateApkDownloader {

    override suspend fun download(
        apk: NightlyUpdateApk,
        downloadUrl: String,
        onProgress: (UpdateDownloadProgress) -> Unit,
    ): UpdateDownloadResult = withContext(ioDispatcher) {
        val directory = downloadDirectory.apply { mkdirs() }
        val partial = File(directory, "${apk.name}.part")
        partial.delete()
        try {
            streamToFile(downloadUrl, partial, apk.sizeBytes, onProgress)
            val verified = partial.length() == apk.sizeBytes &&
                sha256(partial) == apk.sha256.lowercase()
            if (!verified) {
                partial.delete()
                return@withContext UpdateDownloadResult.Failed
            }
            val target = File(directory, apk.name)
            target.delete()
            if (!partial.renameTo(target)) {
                return@withContext UpdateDownloadResult.Failed
            }
            UpdateDownloadResult.Ready(target.absolutePath)
        } catch (cancellation: CancellationException) {
            partial.delete()
            throw cancellation
        } catch (_: Exception) {
            partial.delete()
            UpdateDownloadResult.Failed
        }
    }

    private suspend fun streamToFile(
        url: String,
        file: File,
        expectedSize: Long,
        onProgress: (UpdateDownloadProgress) -> Unit,
    ) {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = CONNECT_TIMEOUT_MILLIS
            readTimeout = READ_TIMEOUT_MILLIS
            instanceFollowRedirects = true
            useCaches = false
            setRequestProperty("Accept", "application/octet-stream")
            setRequestProperty("User-Agent", USER_AGENT)
        }
        try {
            val statusCode = connection.responseCode
            if (statusCode !in 200..299) {
                throw UpdateDownloadHttpException(statusCode)
            }
            val totalBytes = connection.contentLengthLong.takeIf { it > 0L } ?: expectedSize
            connection.inputStream.use { input ->
                file.outputStream().use { output ->
                    copyWithProgress(input, output, totalBytes, onProgress)
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    private suspend fun copyWithProgress(
        input: InputStream,
        output: java.io.OutputStream,
        totalBytes: Long,
        onProgress: (UpdateDownloadProgress) -> Unit,
    ) {
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var bytesRead = 0L
        while (true) {
            coroutineContext.ensureActive()
            val count = input.read(buffer)
            if (count < 0) {
                break
            }
            output.write(buffer, 0, count)
            bytesRead += count
            onProgress(UpdateDownloadProgress(bytesRead = bytesRead, totalBytes = totalBytes))
        }
        output.flush()
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) {
                    break
                }
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    /** A non-2xx response for the APK itself, kept apart from the metadata client's failures. */
    private class UpdateDownloadHttpException(statusCode: Int) :
        IOException("APK download failed with HTTP $statusCode")

    private companion object {
        private const val CONNECT_TIMEOUT_MILLIS = 10_000
        private const val READ_TIMEOUT_MILLIS = 30_000
        private const val USER_AGENT = "Duck-Detector-Android"
    }
}
