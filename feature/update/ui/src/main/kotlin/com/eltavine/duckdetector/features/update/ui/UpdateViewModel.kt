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

package com.eltavine.duckdetector.features.update.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateChecker
import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateApkInstaller
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import com.eltavine.duckdetector.features.update.domain.UpdateInstallResult
import com.eltavine.duckdetector.features.update.presentation.UpdateCheckStatus
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadResolution
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadState
import com.eltavine.duckdetector.features.update.presentation.UpdateUiState
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

internal fun interface UpdateCheckGate {
    fun tryAcquire(): Boolean
}

internal class SingleRunUpdateCheckGate : UpdateCheckGate {
    private val acquired = AtomicBoolean(false)

    override fun tryAcquire(): Boolean = acquired.compareAndSet(false, true)
}

private object ProcessUpdateCheckGate : UpdateCheckGate by SingleRunUpdateCheckGate()

class UpdateViewModel internal constructor(
    private val repository: NightlyUpdateChecker,
    private val currentVersionCode: Int,
    private val currentCommitSha: String,
    private val downloader: UpdateApkDownloader,
    private val installer: UpdateApkInstaller,
    private val automaticCheckGate: UpdateCheckGate = ProcessUpdateCheckGate,
) : ViewModel() {

    private val _uiState = MutableStateFlow(UpdateUiState())
    val uiState: StateFlow<UpdateUiState> = _uiState.asStateFlow()
    private var checkJob: Job? = null
    private var downloadJob: Job? = null

    fun checkAutomatically() {
        if (!automaticCheckGate.tryAcquire()) {
            return
        }
        check(manual = false)
    }

    fun onSettingsUpdateAction() {
        val state = _uiState.value
        if (state.status == UpdateCheckStatus.AVAILABLE && state.availableUpdate != null) {
            _uiState.value = state.copy(isDialogVisible = true)
        } else {
            check(manual = true)
        }
    }

    fun dismissUpdate() {
        _uiState.value = _uiState.value.copy(isDialogVisible = false)
    }

    suspend fun resolveDownload(): UpdateDownloadResolution {
        val displayedManifest = _uiState.value.availableUpdate?.manifest
        return try {
            when (
                val result = repository.check(
                    currentVersionCode = currentVersionCode,
                    currentCommitSha = currentCommitSha,
                )
            ) {
                is UpdateCheckResult.Current -> {
                    _uiState.value = UpdateUiState(status = UpdateCheckStatus.CURRENT)
                    UpdateDownloadResolution.Current
                }

                is UpdateCheckResult.Available -> {
                    val unchanged = result.update.manifest == displayedManifest
                    _uiState.value = _uiState.value.copy(
                        status = UpdateCheckStatus.AVAILABLE,
                        availableUpdate = result.update,
                        isDialogVisible = true,
                        // A still-current APK that was already fetched stays ready to install.
                        download = if (unchanged) _uiState.value.download else UpdateDownloadState.Idle,
                    )
                    if (unchanged) {
                        UpdateDownloadResolution.Ready(result.update.downloadUrl)
                    } else {
                        UpdateDownloadResolution.Refreshed
                    }
                }
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            UpdateDownloadResolution.Failed
        }
    }

    /** Rechecks the manifest, then downloads and verifies the APK in the ViewModel's scope. */
    fun downloadUpdate() {
        if (downloadJob?.isActive == true) {
            return
        }
        downloadJob = viewModelScope.launch {
            when (val resolution = resolveDownload()) {
                is UpdateDownloadResolution.Ready -> downloadApk(resolution.url)
                UpdateDownloadResolution.Failed -> {
                    _uiState.value = _uiState.value.copy(download = UpdateDownloadState.Failed)
                }

                UpdateDownloadResolution.Current,
                UpdateDownloadResolution.Refreshed -> Unit
            }
        }
    }

    /** Opens the package installer for the downloaded APK, closing the dialog once it is shown. */
    fun installDownloaded(): UpdateInstallResult {
        val download = _uiState.value.download
        if (download !is UpdateDownloadState.Ready) {
            return UpdateInstallResult.Failed
        }
        val result = installer.install(download.apkPath)
        if (result == UpdateInstallResult.Launched) {
            _uiState.value = _uiState.value.copy(isDialogVisible = false)
        }
        return result
    }

    private suspend fun downloadApk(downloadUrl: String) {
        val apk = _uiState.value.availableUpdate?.manifest?.apk ?: return
        _uiState.value = _uiState.value.copy(
            download = UpdateDownloadState.Downloading(UpdateDownloadProgress(0L, apk.sizeBytes)),
        )
        val result = downloader.download(apk, downloadUrl) { progress ->
            _uiState.value = _uiState.value.copy(download = UpdateDownloadState.Downloading(progress))
        }
        _uiState.value = _uiState.value.copy(
            download = when (result) {
                is UpdateDownloadResult.Ready -> UpdateDownloadState.Ready(result.apkPath)
                UpdateDownloadResult.Failed -> UpdateDownloadState.Failed
            },
        )
    }

    private fun check(manual: Boolean) {
        checkJob?.cancel()
        _uiState.value = _uiState.value.copy(
            status = UpdateCheckStatus.CHECKING,
            isDialogVisible = false,
        )
        checkJob = viewModelScope.launch {
            try {
                when (
                    val result = repository.check(
                        currentVersionCode = currentVersionCode,
                        currentCommitSha = currentCommitSha,
                    )
                ) {
                    is UpdateCheckResult.Current -> {
                        _uiState.value = UpdateUiState(status = UpdateCheckStatus.CURRENT)
                    }

                    is UpdateCheckResult.Available -> {
                        _uiState.value = UpdateUiState(
                            status = UpdateCheckStatus.AVAILABLE,
                            availableUpdate = result.update,
                            isDialogVisible = true,
                        )
                    }
                }
            } catch (throwable: Throwable) {
                if (throwable is CancellationException) {
                    throw throwable
                }
                _uiState.value = if (manual) {
                    UpdateUiState(status = UpdateCheckStatus.FAILED)
                } else {
                    UpdateUiState(status = UpdateCheckStatus.IDLE)
                }
            }
        }
    }

    companion object {
        fun factory(
            createChecker: () -> NightlyUpdateChecker,
            currentVersionCode: Int,
            currentCommitSha: String,
            downloader: UpdateApkDownloader,
            installer: UpdateApkInstaller,
        ): ViewModelProvider.Factory {
            return object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(modelClass: Class<T>): T {
                    return UpdateViewModel(
                        repository = createChecker(),
                        currentVersionCode = currentVersionCode,
                        currentCommitSha = currentCommitSha,
                        downloader = downloader,
                        installer = installer,
                    ) as T
                }
            }
        }
    }
}
