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
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class UpdateViewModelDownloadLifecycleTest {
    private val dispatcher = StandardTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(dispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    @Test
    fun `unavailable cached apk offers a download retry`() = runTest(dispatcher) {
        var downloads = 0
        val vm = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(availableUpdate()) },
            downloader = UpdateApkDownloader { _, _, _ ->
                downloads++
                UpdateDownloadResult.Ready("/cache/update.apk")
            },
            installer = UpdateApkInstaller { _, _ -> UpdateInstallResult.ApkUnavailable },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        advanceUntilIdle()
        assertEquals(UpdateInstallResult.ApkUnavailable, vm.installDownloaded())
        assertEquals(UpdateDownloadState.Idle, vm.uiState.value.download)
        vm.downloadUpdate()
        advanceUntilIdle()
        assertEquals(2, downloads)
        assertTrue(vm.uiState.value.download is UpdateDownloadState.Ready)
    }

    @Test
    fun `permission settings preserve the verified download`() = runTest(dispatcher) {
        val vm = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(availableUpdate()) },
            downloader = UpdateApkDownloader { _, _, _ -> UpdateDownloadResult.Ready("/cache/update.apk") },
            installer = UpdateApkInstaller { _, _ -> UpdateInstallResult.PermissionRequired },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        advanceUntilIdle()
        val ready = vm.uiState.value.download
        assertEquals(UpdateInstallResult.PermissionRequired, vm.installDownloaded())
        assertEquals(ready, vm.uiState.value.download)
        vm.resolveDownload()
        assertEquals(ready, vm.uiState.value.download)
    }

    @Test
    fun `download exceptions and cancellation leave a retryable state`() = runTest(dispatcher) {
        var calls = 0
        val vm = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(availableUpdate()) },
            downloader = UpdateApkDownloader { _, _, _ ->
                when (++calls) {
                    1 -> error("storage failure")
                    2 -> throw CancellationException("cancelled")
                    else -> UpdateDownloadResult.Ready("/cache/update.apk")
                }
            },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        advanceUntilIdle()
        assertEquals(UpdateDownloadState.Failed(testManifest), vm.uiState.value.download)
        vm.downloadUpdate()
        advanceUntilIdle()
        assertEquals(UpdateDownloadState.Idle, vm.uiState.value.download)
        vm.downloadUpdate()
        advanceUntilIdle()
        assertTrue(vm.uiState.value.download is UpdateDownloadState.Ready)
    }

    @Test
    fun `download progress preserves dismissal and repeated taps start one transfer`() = runTest(dispatcher) {
        var calls = 0
        val release = CompletableDeferred<Unit>()
        lateinit var vm: UpdateViewModel
        vm = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(availableUpdate()) },
            downloader = UpdateApkDownloader { apk, _, progress ->
                calls++
                vm.dismissUpdate()
                progress(UpdateDownloadProgress(1L, apk.sizeBytes))
                release.await()
                UpdateDownloadResult.Ready("/cache/update.apk")
            },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        vm.downloadUpdate()
        runCurrent()
        assertFalse(vm.uiState.value.isDialogVisible)
        assertEquals(1, calls)
        release.complete(Unit)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.isDialogVisible)
        assertTrue(vm.uiState.value.download is UpdateDownloadState.Ready)
    }

    @Test
    fun `closing the dialog during manifest revalidation remains closed`() = runTest(dispatcher) {
        val recheck = CompletableDeferred<UpdateCheckResult>()
        var checks = 0
        val vm = viewModel(
            checker = NightlyUpdateChecker { _, _ ->
                if (++checks == 1) UpdateCheckResult.Available(availableUpdate()) else recheck.await()
            },
            downloader = UpdateApkDownloader { _, _, _ -> UpdateDownloadResult.Ready("/cache/update.apk") },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        runCurrent()
        vm.dismissUpdate()
        recheck.complete(UpdateCheckResult.Available(availableUpdate()))
        advanceUntilIdle()
        assertFalse(vm.uiState.value.isDialogVisible)
        assertTrue(vm.uiState.value.download is UpdateDownloadState.Ready)
    }

    @Test
    fun `late progress after completion cannot replace a ready apk`() = runTest(dispatcher) {
        lateinit var progress: (UpdateDownloadProgress) -> Unit
        val vm = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(availableUpdate()) },
            downloader = UpdateApkDownloader { _, _, callback ->
                progress = callback
                UpdateDownloadResult.Ready("/cache/update.apk")
            },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        advanceUntilIdle()
        val ready = vm.uiState.value.download
        progress(UpdateDownloadProgress(1L, testManifest.apk.sizeBytes))
        assertEquals(ready, vm.uiState.value.download)
    }

    @Test
    fun `old transfer callbacks cannot attach an apk to a newer manifest`() = runTest(dispatcher) {
        var update = availableUpdate()
        val release = CompletableDeferred<Unit>()
        val entered = CompletableDeferred<Unit>()
        val vm = viewModel(
            checker = NightlyUpdateChecker { _, _ -> UpdateCheckResult.Available(update) },
            downloader = UpdateApkDownloader { apk, _, progress ->
                withContext(NonCancellable) {
                    entered.complete(Unit)
                    release.await()
                    progress(UpdateDownloadProgress(apk.sizeBytes, apk.sizeBytes))
                    UpdateDownloadResult.Ready("/cache/old.apk")
                }
            },
        )
        vm.checkAutomatically()
        advanceUntilIdle()
        vm.downloadUpdate()
        runCurrent()
        assertTrue(entered.isCompleted)
        update = availableUpdate(testManifest.copy(versionCode = 501, apk = testManifest.apk.copy(sha256 = "d".repeat(64))))
        vm.resolveDownload()
        release.complete(Unit)
        advanceUntilIdle()
        assertEquals(update.manifest, vm.uiState.value.availableUpdate?.manifest)
        assertEquals(UpdateDownloadState.Idle, vm.uiState.value.download)
        assertEquals(UpdateInstallResult.Failed, vm.installDownloaded())
    }

    @Test
    fun `a delayed older manifest check cannot overwrite a newer result`() = runTest(dispatcher) {
        val delayed = CompletableDeferred<UpdateCheckResult>()
        val newer = availableUpdate(testManifest.copy(versionCode = 501))
        var calls = 0
        val vm = viewModel(NightlyUpdateChecker { _, _ ->
            when (++calls) {
                1 -> UpdateCheckResult.Available(availableUpdate())
                2 -> delayed.await()
                else -> UpdateCheckResult.Available(newer)
            }
        })
        vm.checkAutomatically()
        advanceUntilIdle()
        val olderCheck = async { vm.resolveDownload() }
        runCurrent()
        vm.resolveDownload()
        delayed.complete(UpdateCheckResult.Available(availableUpdate()))
        olderCheck.await()
        assertEquals(newer.manifest, vm.uiState.value.availableUpdate?.manifest)
    }
}
