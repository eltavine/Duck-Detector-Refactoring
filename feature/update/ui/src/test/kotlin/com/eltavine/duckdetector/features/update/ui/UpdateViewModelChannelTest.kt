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

import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateChannel
import com.eltavine.duckdetector.features.update.domain.UpdateChannelPreference
import com.eltavine.duckdetector.features.update.domain.UpdateCheckResult
import com.eltavine.duckdetector.features.update.domain.UpdateChecker
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadProgress
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import com.eltavine.duckdetector.features.update.presentation.UpdateCheckStatus
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class UpdateViewModelChannelTest {
    private val dispatcher = StandardTestDispatcher()
    @Before fun setUp() = Dispatchers.setMain(dispatcher)
    @After fun tearDown() = Dispatchers.resetMain()

    @Test
    fun `checks follow the stored channel and start from the build's`() = runTest(dispatcher) {
        val channels = mutableListOf<UpdateChannel>()
        val viewModel = viewModel(
            checker = UpdateChecker { channel, _, _ ->
                channels += channel
                UpdateCheckResult.Current(testManifest)
            },
            preference = FakeChannelPreference(UpdateChannel.STABLE),
            buildChannel = UpdateChannel.NIGHTLY,
        )

        assertEquals(UpdateChannel.NIGHTLY, viewModel.uiState.value.channel)
        viewModel.checkAutomatically()
        advanceUntilIdle()

        assertEquals(UpdateChannel.STABLE, viewModel.uiState.value.channel)
        assertEquals(listOf(UpdateChannel.STABLE), channels)
    }

    @Test
    fun `choosing a channel stores it and checks it at once`() = runTest(dispatcher) {
        val preference = FakeChannelPreference(UpdateChannel.NIGHTLY)
        val channels = mutableListOf<UpdateChannel>()
        val viewModel = viewModel(
            checker = UpdateChecker { channel, _, _ ->
                channels += channel
                if (channel == UpdateChannel.NIGHTLY) {
                    UpdateCheckResult.Available(availableUpdate())
                } else {
                    UpdateCheckResult.Ahead(testManifest.copy(channel = UpdateChannel.STABLE, versionName = "26.10.0"))
                }
            },
            preference = preference,
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertEquals(UpdateCheckStatus.AVAILABLE, viewModel.uiState.value.status)

        viewModel.selectChannel(UpdateChannel.STABLE)
        assertEquals(UpdateCheckStatus.CHECKING, viewModel.uiState.value.status)
        assertNull(viewModel.uiState.value.availableUpdate)
        advanceUntilIdle()

        assertEquals(UpdateChannel.STABLE, preference.stored)
        assertEquals(listOf(UpdateChannel.NIGHTLY, UpdateChannel.STABLE), channels)
        val state = viewModel.uiState.value
        assertEquals(UpdateChannel.STABLE, state.channel)
        assertEquals(UpdateCheckStatus.AHEAD, state.status)
        assertEquals("26.10.0", state.latestVersionName)
        assertFalse(state.isDialogVisible)

        viewModel.selectChannel(UpdateChannel.STABLE)
        advanceUntilIdle()
        assertEquals(2, channels.size)
    }

    @Test
    fun `a choice made while the stored channel loads is kept`() = runTest(dispatcher) {
        val loaded = CompletableDeferred<Unit>()
        val slowPreference = object : UpdateChannelPreference {
            var stored = UpdateChannel.STABLE

            override suspend fun read(): UpdateChannel {
                val value = stored
                loaded.await()
                return value
            }

            override suspend fun write(channel: UpdateChannel) {
                stored = channel
            }
        }
        val viewModel = viewModel(
            checker = UpdateChecker { _, _, _ -> UpdateCheckResult.Current(testManifest) },
            preference = slowPreference,
            buildChannel = UpdateChannel.STABLE,
        )
        runCurrent()

        viewModel.selectChannel(UpdateChannel.NIGHTLY)
        advanceUntilIdle()
        loaded.complete(Unit)
        advanceUntilIdle()

        assertEquals(UpdateChannel.NIGHTLY, viewModel.uiState.value.channel)
        assertEquals(UpdateChannel.NIGHTLY, slowPreference.stored)
    }


    @Test
    fun `switching channels rejects late download results and uses the selected download channel`() = runTest(dispatcher) {
        val released = CompletableDeferred<Unit>()
        var progress: ((UpdateDownloadProgress) -> Unit)? = null
        val downloadChannels = mutableListOf<UpdateChannel>()
        val vm = viewModel(
            checker = UpdateChecker { channel, _, _ ->
                UpdateCheckResult.Available(availableUpdate(testManifest.copy(channel = channel)))
            },
            downloader = UpdateApkDownloader { _, _, channel, callback ->
                downloadChannels += channel
                if (channel == UpdateChannel.NIGHTLY) {
                    progress = callback
                    withContext(NonCancellable) { released.await() }
                }
                UpdateDownloadResult.Ready("/cache/$channel.apk")
            },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        runCurrent()
        vm.selectChannel(UpdateChannel.STABLE)
        runCurrent()
        released.complete(Unit)
        advanceUntilIdle()
        progress!!(UpdateDownloadProgress(1, 2))
        assertEquals(UpdateDownloadState.Idle, vm.uiState.value.download)
        vm.downloadUpdate()
        advanceUntilIdle()
        assertEquals(listOf(UpdateChannel.NIGHTLY, UpdateChannel.STABLE), downloadChannels)
        val ready = vm.uiState.value.download as UpdateDownloadState.Ready
        assertEquals(UpdateChannel.STABLE, ready.manifest.channel)
        assertEquals("/cache/STABLE.apk", ready.apkPath)
    }
}
