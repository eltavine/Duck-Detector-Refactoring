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

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardUiState
import com.eltavine.duckdetector.features.dashboard.presentation.model.buildDashboardFindings
import com.eltavine.duckdetector.features.dashboard.presentation.model.buildDashboardOverview
import com.eltavine.duckdetector.features.dashboard.presentation.model.dashboardCardOrder
import com.eltavine.duckdetector.features.dashboard.ui.DashboardScreen
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState
import com.eltavine.duckdetector.features.settings.ui.ConsentToggle
import com.eltavine.duckdetector.features.settings.ui.SettingsScreen
import com.eltavine.duckdetector.features.update.data.GitHubAccelerationStore
import com.eltavine.duckdetector.features.update.domain.GitHubAcceleration
import com.eltavine.duckdetector.features.update.presentation.UpdateDownloadResolution
import com.eltavine.duckdetector.features.update.presentation.shouldOfferGitHubAcceleration
import com.eltavine.duckdetector.features.update.ui.GitHubAccelerationDialog
import com.eltavine.duckdetector.features.update.ui.UpdateDialog
import com.eltavine.duckdetector.features.update.ui.UpdateViewModel
import com.eltavine.duckdetector.notifications.ScanProgressNotificationSnapshot
import com.eltavine.duckdetector.notifications.ScanProgressNotifier
import com.eltavine.duckdetector.ui.scan.DetectorScanViewModel
import com.eltavine.duckdetector.ui.shell.AppDestination
import com.eltavine.duckdetector.ui.shell.FloatingAppTabSwitcher
import kotlinx.coroutines.launch

@Composable
internal fun AppReadyShell(
    destination: AppDestination,
    onSelectDestination: (AppDestination) -> Unit,
    consentDecisions: Map<ConsentId, ConsentDecision>,
    notificationPermissionState: com.eltavine.duckdetector.notifications.ScanNotificationPermissionState,
) {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val updateOpenFailedMessage = stringResource(R.string.update_open_failed)
    val scope = rememberCoroutineScope()
    var isResolvingUpdateDownload by remember { mutableStateOf(false) }
    val notifier = remember(appContext) { ScanProgressNotifier(appContext) }
    val updateFactory = remember(context) { updateViewModelFactory(context) }
    val updateViewModel: UpdateViewModel = viewModel(factory = updateFactory)
    val accelerationStore = remember(appContext) { GitHubAccelerationStore.getInstance(appContext) }
    val gitHubAcceleration by accelerationStore.acceleration.collectAsState(initial = null)
    // Closing the offer without answering leaves the choice open, so the next cold start asks again.
    var accelerationOfferDismissed by rememberSaveable { mutableStateOf(false) }
    val appLocale = LocalConfiguration.current.locales[0]
    val offerGitHubAcceleration = !accelerationOfferDismissed &&
        gitHubAcceleration?.let { shouldOfferGitHubAcceleration(it, appLocale) } == true
    // Every detector session starts scanning when it is created, so the catalog order is the order
    // in which detector scans begin.
    val detectorSessions = DetectorFeatures.all.map { feature -> key(feature.id) { feature.rememberSession() } }
    val deviceProfile = DetectorFeatures.deviceProfile.rememberSession()
    // The scan coordinator, the dashboard and the export list detectors by id.
    val detectors = remember(detectorSessions) { detectorSessions.sortedBy { it.id.value } }
    val updateUiState by updateViewModel.uiState.collectAsState()

    // The automatic check waits for the answer to the acceleration offer, so turning acceleration on
    // already sends that first check through gh-proxy.com.
    val automaticUpdateCheckReady = gitHubAcceleration != null && !offerGitHubAcceleration
    LaunchedEffect(updateViewModel, automaticUpdateCheckReady) {
        if (automaticUpdateCheckReady) {
            updateViewModel.checkAutomatically()
        }
    }
    val scanViewModel: DetectorScanViewModel = viewModel(
        factory = remember { DetectorScanViewModel.factory(detectors.map { it.summary }) },
    )
    val scanState by scanViewModel.coordinator.state.collectAsState()
    val detectorSummaries = scanState.detectors
    val isDashboardLoading = scanState.isLoading
    val dashboardScanDurationMillis = scanState.timeline.durationMillis
    val dashboardScanCompletedAtEpochMillis = scanState.timeline.completedAtEpochMillis

    val dashboardState = remember(
        detectorSummaries,
        dashboardScanDurationMillis,
        dashboardScanCompletedAtEpochMillis,
        isDashboardLoading,
    ) {
        DashboardUiState(
            overview = buildDashboardOverview(
                contributions = detectorSummaries,
                scanDurationMillis = dashboardScanDurationMillis,
                scanCompletedAtEpochMillis = dashboardScanCompletedAtEpochMillis,
            ),
            topFindings = buildDashboardFindings(detectorSummaries),
            cardOrder = dashboardCardOrder(detectorSummaries),
            isLoading = isDashboardLoading,
        )
    }
    val settingsState = remember(
        updateUiState.channel,
        updateUiState.status,
        updateUiState.latestVersionName,
        gitHubAcceleration,
    ) {
        SettingsUiState(
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            buildTimeUtc = BuildConfig.BUILD_TIME_UTC,
            buildHash = BuildConfig.BUILD_HASH,
            updateChannel = updateUiState.channel.toSettingsUpdateChannel(),
            updateStatus = updateUiState.status.toSettingsUpdateStatus(),
            latestChannelVersion = updateUiState.latestVersionName,
            gitHubAccelerationEnabled = gitHubAcceleration == GitHubAcceleration.ENABLED,
        )
    }
    val consentToggles = DetectorFeatures.consentCards.map { consentCard ->
        ConsentToggle(
            setting = consentCard.card.setting,
            checked = consentDecisions.getValue(consentCard.consent.id) == ConsentDecision.GRANTED,
            onCheckedChange = { enabled ->
                scope.launch {
                    consentCard.consent.decide(appContext, enabled)
                    detectorSessions.first { it.id == consentCard.detectorId }.rescan()
                }
            },
        )
    }
    val notificationSnapshot = remember(
        detectorSummaries.size,
        detectorSummaries.count { it.ready },
        dashboardState.overview,
        isDashboardLoading,
    ) {
        ScanProgressNotificationSnapshot(
            totalDetectorCount = detectorSummaries.size,
            readyDetectorCount = detectorSummaries.count { it.ready },
            dashboardOverview = dashboardState.overview,
            scanning = isDashboardLoading,
        )
    }

    LaunchedEffect(notificationPermissionState, notificationSnapshot) {
        notifier.update(
            permissionState = notificationPermissionState,
            snapshot = notificationSnapshot,
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {
        when (destination) {
            AppDestination.MAIN -> {
                DashboardScreen(
                    uiState = dashboardState,
                    detectors = detectors,
                    deviceProfile = deviceProfile,
                )
            }

            AppDestination.SETTINGS -> {
                SettingsScreen(
                    uiState = settingsState,
                    consentToggles = consentToggles,
                    onUpdateChannelChange = { channel -> updateViewModel.selectChannel(channel.toUpdateChannel()) },
                    onCheckForUpdates = updateViewModel::onSettingsUpdateAction,
                    onGitHubAccelerationChange = { enabled ->
                        scope.launch { accelerationStore.setEnabled(enabled) }
                    },
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }

        FloatingAppTabSwitcher(
            selectedDestination = destination,
            onSelectDestination = onSelectDestination,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 28.dp),
        )

        if (updateUiState.isDialogVisible && updateUiState.availableUpdate != null) {
            val availableUpdate = requireNotNull(updateUiState.availableUpdate)
            UpdateDialog(
                currentVersionName = BuildConfig.VERSION_NAME,
                update = availableUpdate,
                downloadEnabled = !isResolvingUpdateDownload,
                onDismiss = updateViewModel::dismissUpdate,
                onViewChanges = {
                    if (!openExternalUri(context, availableUpdate.changesUrl)) {
                        Toast.makeText(
                            context,
                            updateOpenFailedMessage,
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                },
                onDownload = {
                    if (!isResolvingUpdateDownload) {
                        isResolvingUpdateDownload = true
                        scope.launch {
                            try {
                                when (val resolution = updateViewModel.resolveDownload()) {
                                    is UpdateDownloadResolution.Ready -> {
                                        if (openExternalUri(context, resolution.url)) {
                                            updateViewModel.dismissUpdate()
                                        } else {
                                            Toast.makeText(
                                                context,
                                                updateOpenFailedMessage,
                                                Toast.LENGTH_SHORT,
                                            ).show()
                                        }
                                    }

                                    UpdateDownloadResolution.Failed -> {
                                        Toast.makeText(
                                            context,
                                            updateOpenFailedMessage,
                                            Toast.LENGTH_SHORT,
                                        ).show()
                                    }

                                    UpdateDownloadResolution.Current,
                                    UpdateDownloadResolution.Refreshed -> Unit
                                }
                            } finally {
                                isResolvingUpdateDownload = false
                            }
                        }
                    }
                },
            )
        }

        if (offerGitHubAcceleration) {
            GitHubAccelerationDialog(
                onEnable = { scope.launch { accelerationStore.setEnabled(true) } },
                onDecline = { scope.launch { accelerationStore.setEnabled(false) } },
                onDismiss = { accelerationOfferDismissed = true },
            )
        }
    }
}

@Composable
internal fun StartupBootstrapLoadingScreen(
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            CircularProgressIndicator()
            Text(
                text = "Preparing startup",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = "Loading agreement state before startup policy review.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
