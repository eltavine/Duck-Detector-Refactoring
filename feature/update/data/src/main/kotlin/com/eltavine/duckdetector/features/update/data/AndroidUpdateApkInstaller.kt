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

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateApkInstaller
import com.eltavine.duckdetector.features.update.domain.UpdateInstallResult
import java.io.File

/**
 * Opens Android's package installer for a downloaded APK.
 *
 * The file lives in the app cache, so it is shared through the app's [FileProvider] rather than a
 * `file:` URI. On Android 8+ the OS refuses the install until the user grants this app the "install
 * unknown apps" permission, so the first attempt routes to that setting instead of failing silently.
 */
internal class AndroidUpdateApkInstaller(
    private val context: Context,
    private val fileProviderAuthority: String,
) : UpdateApkInstaller {

    override fun install(apkPath: String, expectedApk: NightlyUpdateApk): UpdateInstallResult {
        val apk = File(apkPath)
        if (!apk.isFile || !apk.canRead() || apk.length() != expectedApk.sizeBytes) {
            return UpdateInstallResult.ApkUnavailable
        }
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                !context.packageManager.canRequestPackageInstalls()
            ) {
                openUnknownAppSourcesSettings()
            } else {
                launchInstaller(apk)
            }
        } catch (_: Exception) {
            UpdateInstallResult.Failed
        }
    }

    private fun openUnknownAppSourcesSettings(): UpdateInstallResult {
        val intent = Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        return try {
            context.startActivity(intent)
            UpdateInstallResult.PermissionRequired
        } catch (_: Exception) {
            UpdateInstallResult.Failed
        }
    }

    private fun launchInstaller(apk: File): UpdateInstallResult {
        return try {
            val apkUri = FileProvider.getUriForFile(context, fileProviderAuthority, apk)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(apkUri, APK_MIME_TYPE)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            UpdateInstallResult.Launched
        } catch (_: Exception) {
            UpdateInstallResult.Failed
        }
    }

    private companion object {
        private const val APK_MIME_TYPE = "application/vnd.android.package-archive"
    }
}

/** Downloads go to a cache subdirectory the app's FileProvider is configured to serve. */
fun createUpdateApkDownloader(appContext: Context): UpdateApkDownloader =
    HttpUpdateApkDownloader(downloadDirectory = File(appContext.cacheDir, UPDATE_DOWNLOAD_DIRECTORY))

fun createUpdateApkInstaller(appContext: Context): UpdateApkInstaller =
    AndroidUpdateApkInstaller(
        context = appContext,
        fileProviderAuthority = "${appContext.packageName}.update.fileprovider",
    )

private const val UPDATE_DOWNLOAD_DIRECTORY = "updates"
