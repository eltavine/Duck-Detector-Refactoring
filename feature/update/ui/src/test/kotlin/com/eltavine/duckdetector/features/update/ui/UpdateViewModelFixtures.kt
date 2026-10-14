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

import com.eltavine.duckdetector.features.update.domain.AvailableNightlyUpdate
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateApk
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateChecker
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateCommit
import com.eltavine.duckdetector.features.update.domain.NightlyUpdateManifest
import com.eltavine.duckdetector.features.update.domain.UpdateApkDownloader
import com.eltavine.duckdetector.features.update.domain.UpdateApkInstaller
import com.eltavine.duckdetector.features.update.domain.UpdateChangelogEntry
import com.eltavine.duckdetector.features.update.domain.UpdateDownloadResult
import com.eltavine.duckdetector.features.update.domain.UpdateInstallResult

internal val testManifest = NightlyUpdateManifest(
    schemaVersion = 1,
    channel = "nightly",
    branch = "master",
    versionName = "2026.08.08-${TEST_HEAD_SHA.take(12)}",
    versionCode = 500,
    commit = NightlyUpdateCommit(
        sha = TEST_HEAD_SHA,
        subject = "feat(update): publish Nightly metadata",
        body = "Publish metadata after the APK is available.",
        authorName = "Duck Contributor",
        authoredAt = "2026-08-08T12:20:00Z",
    ),
    builtAtUtc = "2026-08-08T12:30:00Z",
    apk = NightlyUpdateApk(
        name = "Duck.Detector-test.apk",
        downloadUrl = "https://github.com/eltavine/Duck-Detector-Refactoring/releases/download/nightly/Duck.Detector-test.apk",
        sizeBytes = 12_345_678L,
        sha256 = "c".repeat(64),
    ),
)

internal fun viewModel(
    checker: NightlyUpdateChecker,
    downloader: UpdateApkDownloader = UpdateApkDownloader { _, _, _ -> UpdateDownloadResult.Failed },
    installer: UpdateApkInstaller = UpdateApkInstaller { _, _ -> UpdateInstallResult.Failed },
): UpdateViewModel {
    return UpdateViewModel(
        repository = checker,
        currentVersionCode = 400,
        currentCommitSha = TEST_BASE_SHA,
        downloader = downloader,
        installer = installer,
        automaticCheckGate = SingleRunUpdateCheckGate(),
    )
}

internal fun availableUpdate(
    updateManifest: NightlyUpdateManifest = testManifest,
    downloadUrl: String = updateManifest.apk.downloadUrl,
): AvailableNightlyUpdate {
    return AvailableNightlyUpdate(
        manifest = updateManifest,
        changelog = listOf(
            UpdateChangelogEntry(
                sha = updateManifest.commit.sha,
                subject = updateManifest.commit.subject,
                authorName = updateManifest.commit.authorName,
            ),
        ),
        remainingCommitCount = 0,
        downloadUrl = downloadUrl,
        compareUrl =
            "https://github.com/eltavine/Duck-Detector-Refactoring/compare/$TEST_BASE_SHA...${updateManifest.commit.sha}",
    )
}

private const val TEST_HEAD_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val TEST_BASE_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
