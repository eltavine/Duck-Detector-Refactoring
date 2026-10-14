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
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.domain.UpdateChannelPreference
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import com.eltavine.duckdetector.features.update.domain.UpdateChecker
import com.eltavine.duckdetector.features.update.presentation.UpdateCheckStatus
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadResolution
import com.eltavine.duckdetector.features.update.presentation.UpdateUiState
import java.util.concurrent.atomic.AtomicBoolean
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
    private val automaticCheckGate: UpdateCheckGate = ProcessUpdateCheckGate,
) : ViewModel() {

    private val _uiState = MutableStateFlow(UpdateUiState(channel = buildChannel))
    val uiState: StateFlow<UpdateUiState> = _uiState.asStateFlow()
    private var checkJob: Job? = null
    private var channelChosenHere = false

    init {
        viewModelScope.launch {
            val stored = channelPreference.read()
            // A choice made while the stored channel loaded is newer than what was stored.
            if (!channelChosenHere) {
                _uiState.update { state -> state.copy(channel = stored) }
            }
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
            _uiState.value = state.copy(isDialogVisible = true)
        } else {
            check(manual = true)
        }
    }

    /** Follows [channel] from now on and checks it at once, dropping what the other channel found. */
    fun selectChannel(channel: UpdateChannel) {
        if (channel == _uiState.value.channel) {
            return
        }
        channelChosenHere = true
        checkJob?.cancel()
        _uiState.value = UpdateUiState(channel = channel, status = UpdateCheckStatus.CHECKING)
        checkJob = viewModelScope.launch {
            channelPreference.write(channel)
            runCheck(channel, manual = true)
        }
    }

    fun dismissUpdate() {
        _uiState.value = _uiState.value.copy(isDialogVisible = false)
    }

    suspend fun resolveDownload(): UpdateDownloadResolution {
        val state = _uiState.value
        val displayedManifest = state.availableUpdate?.manifest
        return try {
            val result = repository.check(state.channel, currentVersionCode, currentCommitSha)
            _uiState.value = stateFor(state.channel, result)
            when (result) {
                is UpdateCheckResult.Current,
                is UpdateCheckResult.Ahead -> UpdateDownloadResolution.Current

                is UpdateCheckResult.Available -> if (result.update.manifest == displayedManifest) {
                    UpdateDownloadResolution.Ready(result.update.downloadUrl)
                } else {
                    UpdateDownloadResolution.Refreshed
                }
            }
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            UpdateDownloadResolution.Failed
        }
    }

    private fun check(manual: Boolean) {
        checkJob?.cancel()
        _uiState.value = _uiState.value.copy(
            status = UpdateCheckStatus.CHECKING,
            isDialogVisible = false,
        )
        checkJob = viewModelScope.launch {
            runCheck(channelPreference.read(), manual)
        }
    }

    private suspend fun runCheck(channel: UpdateChannel, manual: Boolean) {
        try {
            val result = repository.check(channel, currentVersionCode, currentCommitSha)
            _uiState.value = stateFor(channel, result)
        } catch (throwable: Throwable) {
            if (throwable is CancellationException) {
                throw throwable
            }
            _uiState.value = UpdateUiState(
                channel = channel,
                status = if (manual) UpdateCheckStatus.FAILED else UpdateCheckStatus.IDLE,
            )
        }
    }

    private fun stateFor(channel: UpdateChannel, result: UpdateCheckResult): UpdateUiState = when (result) {
        is UpdateCheckResult.Current -> UpdateUiState(
            channel = channel,
            status = UpdateCheckStatus.CURRENT,
            latestVersionName = result.manifest.versionName,
        )

        is UpdateCheckResult.Ahead -> UpdateUiState(
            channel = channel,
            status = UpdateCheckStatus.AHEAD,
            latestVersionName = result.manifest.versionName,
        )

        is UpdateCheckResult.Available -> UpdateUiState(
            channel = channel,
            status = UpdateCheckStatus.AVAILABLE,
            availableUpdate = result.update,
            isDialogVisible = true,
        )
    }

    companion object {
        fun factory(
            createChecker: () -> UpdateChecker,
            createChannelPreference: () -> UpdateChannelPreference,
            buildChannel: UpdateChannel,
            currentVersionCode: Int,
            currentCommitSha: String,
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
                    ) as T
                }
            }
        }
    }
}
