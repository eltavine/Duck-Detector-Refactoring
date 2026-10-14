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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class UpdateViewModelTest {
    private val dispatcher: TestDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `automatic check runs once while manual check can run again`() = runTest(dispatcher) {
        var calls = 0
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ ->
                calls += 1
                UpdateCheckResult.Current(testManifest)
            },
        )

        viewModel.checkAutomatically()
        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertEquals(1, calls)
        assertEquals(UpdateCheckStatus.CURRENT, viewModel.uiState.value.status)

        viewModel.onSettingsUpdateAction()
        advanceUntilIdle()
        assertEquals(2, calls)
    }

    @Test
    fun `automatic failure is silent while manual failure is visible`() = runTest(dispatcher) {
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> error("offline") },
        )

        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertEquals(UpdateCheckStatus.IDLE, viewModel.uiState.value.status)

        viewModel.onSettingsUpdateAction()
        advanceUntilIdle()
        assertEquals(UpdateCheckStatus.FAILED, viewModel.uiState.value.status)
    }

    @Test
    fun `dismissal lasts for the current state and settings can reopen details`() = runTest(dispatcher) {
        var calls = 0
        val available = availableUpdate()
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ ->
                calls += 1
                UpdateCheckResult.Available(available)
            },
        )

        viewModel.checkAutomatically()
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value.isDialogVisible)

        viewModel.dismissUpdate()
        assertFalse(viewModel.uiState.value.isDialogVisible)

        viewModel.onSettingsUpdateAction()
        assertTrue(viewModel.uiState.value.isDialogVisible)
        assertEquals(1, calls)

        val nextProcessViewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
        )
        nextProcessViewModel.checkAutomatically()
        advanceUntilIdle()
        assertTrue(nextProcessViewModel.uiState.value.isDialogVisible)
    }

    @Test
    fun `single run gate only grants its first acquisition`() {
        val gate = SingleRunUpdateCheckGate()

        assertTrue(gate.tryAcquire())
        assertFalse(gate.tryAcquire())
    }

    @Test
    fun `download resolution rechecks an unchanged manifest before opening`() = runTest(dispatcher) {
        val available = availableUpdate()
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()

        val resolution = viewModel.resolveDownload()

        assertEquals(
            UpdateDownloadResolution.Ready(availableUpdate()),
            resolution,
        )
    }

    @Test
    fun `download opens through the route of the check that resolves it`() = runTest(dispatcher) {
        val proxiedUrl = "https://gh-proxy.com/${testManifest.apk.downloadUrl}"
        var calls = 0
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ ->
                calls += 1
                UpdateCheckResult.Available(
                    if (calls == 1) availableUpdate() else availableUpdate(downloadUrl = proxiedUrl),
                )
            },
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()

        val resolution = viewModel.resolveDownload()

        assertEquals(UpdateDownloadResolution.Ready(availableUpdate(downloadUrl = proxiedUrl)), resolution)
    }

    @Test
    fun `download resolution refreshes a superseded Nightly instead of opening its stale URL`() =
        runTest(dispatcher) {
            val newerManifest = testManifest.copy(
                versionName = "2026.08.09-${NEWER_HEAD_SHA.take(12)}",
                versionCode = 501,
                commit = testManifest.commit.copy(sha = NEWER_HEAD_SHA),
                apk = testManifest.apk.copy(
                    name = "Duck.Detector-newer.apk",
                    downloadUrl =
                        "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/Duck.Detector-newer.apk",
                ),
            )
            var calls = 0
            val viewModel = viewModel(
                checker = NightlyUpdateChecker { _, _ ->
                    calls += 1
                    UpdateCheckResult.Available(
                        if (calls == 1) availableUpdate() else availableUpdate(newerManifest),
                    )
                },
            )
            viewModel.checkAutomatically()
            advanceUntilIdle()

            val resolution = viewModel.resolveDownload()

            assertEquals(UpdateDownloadResolution.Refreshed, resolution)
            assertEquals(newerManifest, viewModel.uiState.value.availableUpdate?.manifest)
            assertTrue(viewModel.uiState.value.isDialogVisible)
        }

    @Test
    fun `download verifies the resolved url and exposes a ready apk for install`() = runTest(dispatcher) {
        val available = availableUpdate()
        var downloadedUrl: String? = null
        var installedPath: String? = null
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
            downloader = UpdateApkDownloader { apk, url, onProgress ->
                downloadedUrl = url
                onProgress(UpdateDownloadProgress(bytesRead = apk.sizeBytes, totalBytes = apk.sizeBytes))
                UpdateDownloadResult.Ready(apkPath = "/tmp/${apk.name}")
            },
            installer = UpdateApkInstaller { path, _ ->
                installedPath = path
                UpdateInstallResult.Launched
            },
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()

        viewModel.downloadUpdate()
        advanceUntilIdle()

        assertEquals(testManifest.apk.downloadUrl, downloadedUrl)
        assertEquals(
            UpdateDownloadState.Ready(testManifest, "/tmp/${testManifest.apk.name}"),
            viewModel.uiState.value.download,
        )
        assertTrue(viewModel.uiState.value.isDialogVisible)

        assertEquals(UpdateInstallResult.Launched, viewModel.installDownloaded())
        assertEquals("/tmp/${testManifest.apk.name}", installedPath)
        assertFalse(viewModel.uiState.value.isDialogVisible)
    }

    @Test
    fun `a failed download surfaces a retryable state`() = runTest(dispatcher) {
        val available = availableUpdate()
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
            downloader = UpdateApkDownloader { _, _, _ -> UpdateDownloadResult.Failed },
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()

        viewModel.downloadUpdate()
        advanceUntilIdle()

        assertEquals(UpdateDownloadState.Failed(testManifest), viewModel.uiState.value.download)
        assertTrue(viewModel.uiState.value.isDialogVisible)
    }

    @Test
    fun `installing without a downloaded apk does nothing`() = runTest(dispatcher) {
        val available = availableUpdate()
        val viewModel = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(available) },
        )
        viewModel.checkAutomatically()
        advanceUntilIdle()

        assertEquals(UpdateInstallResult.Failed, viewModel.installDownloaded())
        assertTrue(viewModel.uiState.value.isDialogVisible)
    }

    private companion object {
        private const val NEWER_HEAD_SHA = "cccccccccccccccccccccccccccccccccccccccc"
    }
}
