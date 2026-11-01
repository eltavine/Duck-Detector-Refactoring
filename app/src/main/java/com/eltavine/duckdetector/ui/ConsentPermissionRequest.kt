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

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.platform.LocalContext
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.ui.shell.DetectorConsentCard
import kotlinx.coroutines.launch

/** Permission prompts only follow an explicit consent action, never a scan or recomposition. */
@Composable
internal fun rememberConsentDecisionHandler(onChanged: (DetectorId) -> Unit = {}): (DetectorConsentCard, Boolean) -> Unit {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pendingId by rememberSaveable { mutableStateOf<String?>(null) }
    val latestOnChanged by rememberUpdatedState(onChanged)
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        pendingId?.let { latestOnChanged(DetectorId(it)) }
        pendingId = null
    }
    return { card, enabled ->
        scope.launch {
            card.consent.decide(context.applicationContext, enabled)
            val missing = card.card.runtimePermissions.filter {
                context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
            }
            if (enabled && missing.isNotEmpty()) {
                pendingId = card.detectorId.value
                permissionLauncher.launch(missing.toTypedArray())
            } else latestOnChanged(card.detectorId)
        }
    }
}

@Composable
internal fun rememberAppPermissionSettings(onReturn: () -> Unit = {}): () -> Unit {
    val context = LocalContext.current
    val latestOnReturn by rememberUpdatedState(onReturn)
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        latestOnReturn()
    }
    return {
        launcher.launch(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.fromParts("package", context.packageName, null)))
    }
}
