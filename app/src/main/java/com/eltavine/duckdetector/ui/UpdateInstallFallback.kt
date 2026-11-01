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

package com.eltavine.duckdetector.ui

import android.content.Context
import android.widget.Toast
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.update.domain.UpdateInstallResult
import com.eltavine.duckdetector.features.update.domain.httpsUpdateDownloadUrlOrNull

internal fun showUpdateInstallFeedback(
    context: Context,
    result: UpdateInstallResult,
    downloadUrl: String?,
) {
    val message = when (result) {
        UpdateInstallResult.Launched -> return
        UpdateInstallResult.PermissionRequired -> R.string.update_install_permission_required
        UpdateInstallResult.ApkUnavailable,
        UpdateInstallResult.Failed -> {
            val fallback = fallbackFromFailedLocalInstall(
                result = result,
                downloadUrl = downloadUrl,
                copy = { url ->
                    copyPlainTextToClipboard(
                        context,
                        "Duck Detector APK",
                        url,
                        context.getString(R.string.update_install_link_copied),
                    )
                },
                open = { url -> openExternalUri(context, url) },
            )
            when {
                fallback?.let { it.copied && it.browserOpened } == true -> R.string.update_install_fallback_copied_opened
                fallback?.copied == true -> R.string.update_install_fallback_copied_only
                fallback?.browserOpened == true -> R.string.update_install_fallback_opened_only
                result == UpdateInstallResult.ApkUnavailable -> R.string.update_apk_unavailable
                else -> R.string.update_install_failed
            }
        }
    }
    Toast.makeText(context, message, Toast.LENGTH_LONG).show()
}

internal data class UpdateInstallFallbackResult(
    val copied: Boolean,
    val browserOpened: Boolean,
)

/**
 * A local APK handoff failure offers the already selected download route as a fallback.
 * Clipboard and browser are independent: failure of either must not prevent the other.
 *
 * A successful installer launch cannot tell us whether the user later completed installation.
 */
internal fun fallbackFromFailedLocalInstall(
    result: UpdateInstallResult,
    downloadUrl: String?,
    copy: (String) -> Boolean,
    open: (String) -> Boolean,
): UpdateInstallFallbackResult? {
    if (result != UpdateInstallResult.Failed && result != UpdateInstallResult.ApkUnavailable) return null
    val url = httpsUpdateDownloadUrlOrNull(downloadUrl)
        ?: return UpdateInstallFallbackResult(copied = false, browserOpened = false)
    val copied = runCatching { copy(url) }.getOrDefault(false)
    val opened = runCatching { open(url) }.getOrDefault(false)
    return UpdateInstallFallbackResult(copied, opened)
}
