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
import com.eltavine.duckdetector.features.update.domain.AvailableUpdate
import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateApkInstaller
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.domain.UpdateChannelPreference
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import com.eltavine.duckdetector.features.update.domain.UpdateChecker
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import com.eltavine.duckdetector.features.update.domain.UpdateInstallResult
import com.eltavine.duckdetector.features.update.domain.UpdateManifest
import com.eltavine.duckdetector.features.update.presentation.UpdateCheckStatus
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadResolution
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadState
import com.eltavine.duckdetector.features.update.presentation.UpdateUiState
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
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
    private val repository: UpdateChecker,
    private val channelPreference: UpdateChannelPreference,
    buildChannel: UpdateChannel,
    private val currentVersionCode: Int,
    private val currentCommitSha: String,
    private val downloader: UpdateApkDownloader,
    private val installer: UpdateApkInstaller,
    private val automaticCheckGate: UpdateCheckGate = ProcessUpdateCheckGate,
) : ViewModel() {

    private val _uiState = MutableStateFlow(UpdateUiState(channel = buildChannel))
    val uiState: StateFlow<UpdateUiState> = _uiState.asStateFlow()
    private var checkJob: Job? = null
    private var downloadJob: Job? = null
    private val downloadGeneration = AtomicLong()
    private var checkGeneration = 0L
    private var channelChosenHere = false

    init {
        viewModelScope.launch {
            val stored = channelPreference.read()
            // A choice made while the stored channel loaded supersedes the stored value.
            if (!channelChosenHere) {
                _uiState.update { it.copy(channel = stored) }
            }
        }
    }

    /** Starts following [channel] and invalidates work owned by the previous channel. */
    fun selectChannel(channel: UpdateChannel) {
        if (channel == _uiState.value.channel) return
        channelChosenHere = true
        checkJob?.cancel()
        val generation = ++checkGeneration
        invalidateDownload()
        _uiState.value = UpdateUiState(channel = channel, status = UpdateCheckStatus.CHECKING)
        checkJob = viewModelScope.launch {
            channelPreference.write(channel)
            runCheck(channel, manual = true, generation = generation)
        }
    }

    fun checkAutomatically() {
        if (!automaticCheckGate.tryAcquire()) {
            return
        }
        check(manual = false)
    }

    fun onSettingsUpdateAction() {
        val state = _uiState.value
        if (state.status == UpdateCheckStatus.AVAILABLE && state.availableUpdate != null) {
            _uiState.update { it.copy(isDialogVisible = true) }
        } else {
            check(manual = true)
        }
    }

    fun dismissUpdate() {
        _uiState.update { it.copy(isDialogVisible = false) }
    }

    suspend fun resolveDownload(): UpdateDownloadResolution {
        checkJob?.cancel()
        val generation = ++checkGeneration
        val channel = _uiState.value.channel
        val displayedManifest = _uiState.value.availableUpdate?.manifest
        return try {
            val result = repository.check(channel, currentVersionCode, currentCommitSha)
            if (generation != checkGeneration) return UpdateDownloadResolution.Failed
            when (result) {
                is UpdateCheckResult.Current,
                is UpdateCheckResult.Ahead -> {
                    invalidateDownload()
                    acceptResult(channel, result)
                    UpdateDownloadResolution.Current
                }
                is UpdateCheckResult.Available -> {
                    val unchanged = result.update.manifest == displayedManifest
                    acceptUpdate(result.update, preserveDismissal = unchanged)
                    if (unchanged) {
                        UpdateDownloadResolution.Ready(result.update)
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

    /** The resolved update is an immutable snapshot used by every progress and completion callback. */
    fun downloadUpdate() {
        if (downloadJob?.isActive == true) return
        val manifest = _uiState.value.availableUpdate?.manifest ?: return
        val generation = downloadGeneration.incrementAndGet()
        _uiState.update {
            it.copy(
                download = UpdateDownloadState.Downloading(
                    manifest,
                    UpdateDownloadProgress(0L, manifest.apk.sizeBytes),
                ),
            )
        }
        downloadJob = viewModelScope.launch {
            try {
                when (val resolution = resolveDownload()) {
                    is UpdateDownloadResolution.Ready -> {
                        if (downloadGeneration.get() == generation) downloadApk(resolution.update, generation)
                    }
                    UpdateDownloadResolution.Failed -> updateDownload(generation, manifest) {
                        it.copy(download = UpdateDownloadState.Failed(manifest))
                    }
                    UpdateDownloadResolution.Current,
                    UpdateDownloadResolution.Refreshed -> Unit
                }
            } catch (cancellation: CancellationException) {
                updateDownload(generation, manifest) { it.copy(download = UpdateDownloadState.Idle) }
                throw cancellation
            } catch (_: Exception) {
                updateDownload(generation, manifest) { it.copy(download = UpdateDownloadState.Failed(manifest)) }
            }
        }
    }

    fun installDownloaded(): UpdateInstallResult {
        val state = _uiState.value
        val download = state.download as? UpdateDownloadState.Ready ?: return UpdateInstallResult.Failed
        if (download.manifest != state.availableUpdate?.manifest) {
            _uiState.update { it.copy(download = UpdateDownloadState.Idle) }
            return UpdateInstallResult.ApkUnavailable
        }
        val result = try {
            installer.install(download.apkPath, download.manifest.apk)
        } catch (_: Exception) {
            UpdateInstallResult.Failed
        }
        when (result) {
            UpdateInstallResult.Launched -> _uiState.update { it.copy(isDialogVisible = false) }
            UpdateInstallResult.ApkUnavailable -> _uiState.update {
                it.copy(download = UpdateDownloadState.Idle)
            }
            UpdateInstallResult.PermissionRequired,
            UpdateInstallResult.Failed -> Unit
        }
        return result
    }

    private suspend fun downloadApk(update: AvailableUpdate, generation: Long) {
        val manifest = update.manifest
        val result = downloader.download(manifest.apk, update.downloadUrl, manifest.channel) { progress ->
            updateDownload(generation, manifest) {
                if (it.download is UpdateDownloadState.Downloading) {
                    it.copy(download = UpdateDownloadState.Downloading(manifest, progress))
                } else {
                    it
                }
            }
        }
        updateDownload(generation, manifest) {
            it.copy(
                download = when (result) {
                    is UpdateDownloadResult.Ready -> UpdateDownloadState.Ready(manifest, result.apkPath)
                    UpdateDownloadResult.Failed -> UpdateDownloadState.Failed(manifest)
                },
            )
        }
    }

    private inline fun updateDownload(
        generation: Long,
        manifest: UpdateManifest,
        transform: (UpdateUiState) -> UpdateUiState,
    ) {
        _uiState.update {
            if (downloadGeneration.get() == generation && it.availableUpdate?.manifest == manifest) {
                transform(it)
            } else {
                it
            }
        }
    }

    private fun invalidateDownload() {
        downloadGeneration.incrementAndGet()
        downloadJob?.cancel()
        downloadJob = null
    }

    private fun acceptUpdate(update: AvailableUpdate, preserveDismissal: Boolean = false) {
        val unchanged = _uiState.value.availableUpdate?.manifest == update.manifest
        if (!unchanged) invalidateDownload()
        _uiState.update {
            it.copy(
                status = UpdateCheckStatus.AVAILABLE,
                availableUpdate = update,
                isDialogVisible = if (preserveDismissal) it.isDialogVisible else true,
                download = if (unchanged) it.download else UpdateDownloadState.Idle,
            )
        }
    }

    private fun check(manual: Boolean) {
        checkJob?.cancel()
        val generation = ++checkGeneration
        invalidateDownload()
        _uiState.update {
            it.copy(status = UpdateCheckStatus.CHECKING, isDialogVisible = false, download = UpdateDownloadState.Idle)
        }
        checkJob = viewModelScope.launch {
            val channel = if (channelChosenHere) _uiState.value.channel else channelPreference.read()
            if (generation != checkGeneration) return@launch
            _uiState.update { it.copy(channel = channel) }
            runCheck(channel, manual, generation)
        }
    }

    private suspend fun runCheck(channel: UpdateChannel, manual: Boolean, generation: Long) {
        try {
            val result = repository.check(channel, currentVersionCode, currentCommitSha)
            if (generation == checkGeneration) acceptResult(channel, result)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            if (generation == checkGeneration) {
                _uiState.value = UpdateUiState(
                    channel = channel,
                    status = if (manual) UpdateCheckStatus.FAILED else UpdateCheckStatus.IDLE,
                )
            }
        }
    }

    private fun acceptResult(channel: UpdateChannel, result: UpdateCheckResult) {
        when (result) {
            is UpdateCheckResult.Current -> _uiState.value = UpdateUiState(
                channel = channel,
                status = UpdateCheckStatus.CURRENT,
                latestVersionName = result.manifest.versionName,
            )
            is UpdateCheckResult.Ahead -> _uiState.value = UpdateUiState(
                channel = channel,
                status = UpdateCheckStatus.AHEAD,
                latestVersionName = result.manifest.versionName,
            )
            is UpdateCheckResult.Available -> acceptUpdate(result.update)
        }
    }

    companion object {
        fun factory(
            createChecker: () -> UpdateChecker,
            createChannelPreference: () -> UpdateChannelPreference,
            buildChannel: UpdateChannel,
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
                        channelPreference = createChannelPreference(),
                        buildChannel = buildChannel,
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
