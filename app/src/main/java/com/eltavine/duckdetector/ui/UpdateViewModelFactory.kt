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
import androidx.lifecycle.ViewModelProvider
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.features.update.data.createNightlyUpdateChecker
import com.eltavine.duckdetector.features.update.data.createUpdateApkDownloader
import com.eltavine.duckdetector.features.update.data.createUpdateApkInstaller
import com.eltavine.duckdetector.features.update.ui.UpdateViewModel

internal fun updateViewModelFactory(context: Context): ViewModelProvider.Factory {
    val appContext = context.applicationContext
    return UpdateViewModel.factory(
        createChecker = { createNightlyUpdateChecker(appContext) },
        currentVersionCode = BuildConfig.VERSION_CODE,
        currentCommitSha = BuildConfig.BUILD_HASH,
        downloader = createUpdateApkDownloader(appContext),
        installer = createUpdateApkInstaller(appContext),
    )
}
