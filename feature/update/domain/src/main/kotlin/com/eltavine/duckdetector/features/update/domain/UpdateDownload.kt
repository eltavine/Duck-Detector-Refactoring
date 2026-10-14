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

package com.eltavine.duckdetector.features.update.domain

/** Maximum accepted Nightly APK size, independent of remote metadata. */
const val MAX_UPDATE_APK_BYTES: Long = 256L * 1024 * 1024

/** Bytes transferred so far and the total the manifest advertised. */
data class UpdateDownloadProgress(
    val bytesRead: Long,
    val totalBytes: Long,
) {
    /** 0f..1f, or 0f when the total is unknown. */
    val fraction: Float
        get() = if (totalBytes <= 0L) 0f else (bytesRead.toFloat() / totalBytes).coerceIn(0f, 1f)
}

sealed interface UpdateDownloadResult {
    /** The verified APK on local storage, ready to hand to the package installer. */
    data class Ready(val apkPath: String) : UpdateDownloadResult

    data object Failed : UpdateDownloadResult
}

sealed interface UpdateInstallResult {
    /** Android's package installer was opened for the APK. */
    data object Launched : UpdateInstallResult

    /** The user must first allow this app to install unknown apps; settings were opened. */
    data object PermissionRequired : UpdateInstallResult

    /** The cached APK has disappeared, changed size, or is no longer readable. Download it again. */
    data object ApkUnavailable : UpdateInstallResult

    data object Failed : UpdateInstallResult
}

/**
 * Streams the update APK to local storage and verifies its size and SHA-256 against metadata
 * obtained independently from the official release before reporting [UpdateDownloadResult.Ready].
 */
fun interface UpdateApkDownloader {
    suspend fun download(
        apk: NightlyUpdateApk,
        downloadUrl: String,
        onProgress: (UpdateDownloadProgress) -> Unit,
    ): UpdateDownloadResult
}

/** Hands a downloaded APK to Android's package installer through a content URI. */
fun interface UpdateApkInstaller {
    fun install(apkPath: String, expectedApk: NightlyUpdateApk): UpdateInstallResult
}
