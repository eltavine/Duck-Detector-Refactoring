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
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.text.BasicText
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.outlined.Home as HomeOutline
import androidx.compose.material.icons.outlined.Settings as SettingsOutline
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
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.navigation.DuckNavHost
import com.eltavine.duckdetector.core.navigation.DuckRoute
import com.eltavine.duckdetector.core.navigation.rememberDuckRoutes
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardUiState
import com.eltavine.duckdetector.features.dashboard.presentation.model.buildDashboardFindings
import com.eltavine.duckdetector.features.dashboard.presentation.model.buildDashboardOverview
import com.eltavine.duckdetector.features.dashboard.presentation.model.dashboardCardOrder
import com.eltavine.duckdetector.features.dashboard.ui.DashboardScreen
import com.eltavine.duckdetector.features.dashboard.ui.DashboardTelegramAction
import com.eltavine.duckdetector.features.dashboard.ui.DashboardTopBarBrandIcon
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState
import com.eltavine.duckdetector.features.settings.ui.ConsentToggle
import com.eltavine.duckdetector.features.settings.ui.SettingsScreen
import com.eltavine.duckdetector.features.settings.ui.licenses.OpenSourceLicensesScreen
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
import io.github.xiaotong6666.uihelper.chrome.AdaptiveNavigationShell
import io.github.xiaotong6666.uihelper.chrome.NavigationShellItem
import io.github.xiaotong6666.uihelper.chrome.NavigationShellPagerGesturePolicy
import io.github.xiaotong6666.uihelper.adaptive.WrapSafeText
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue
import kotlinx.coroutines.launch
import io.github.xiaotong6666.uihelper.dialog.rememberRetainedDialogPayload
import io.github.xiaotong6666.uihelper.mode.UiMode

@Composable
internal fun AppReadyShell(
    destination: AppDestination,
    onSelectDestination: (AppDestination) -> Unit,
    onUiModeChange: (UiMode) -> Unit,
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
    val visibleUpdate = updateUiState.availableUpdate.takeIf { updateUiState.isDialogVisible }
    val updateDialogPayload = rememberRetainedDialogPayload(visibleUpdate)

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

    // Keep one MIUIX navigation stack for both skins. The tab pager remains within Main,
    // and cannot intercept the predictive-back gesture of the Licenses route on top of it.
    val navigator = rememberDuckRoutes()
    val openLicenses: () -> Unit = {
        navigator.pushUnique(DuckRoute.Licenses)
    }
    val backFromLicenses: () -> Unit = {
        navigator.pop()
    }

    Box(modifier = Modifier.fillMaxSize()) {
        DuckNavHost(
            backStack = navigator.backStack,
            onBack = backFromLicenses,
            main = {
                // One route owner and one tab pager for both skins. Page state, title and
                // bottom-bar selection track the physically visible page during a gesture.
                AdaptiveNavigationShell(
                    items = listOf(
                        NavigationShellItem(
                            title = stringResource(R.string.navigation_home),
                            topBarTitle = "Duck Detector",
                            compactTopBarTitle = "Duck Detector",
                            icon = Icons.Outlined.HomeOutline,
                            selectedIcon = Icons.Rounded.Home,
                            leadingContent = { DashboardTopBarBrandIcon() },
                            largeTitleLeadingContent = { DashboardTopBarBrandIcon() },
                            materialTitleContent = {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    DashboardTopBarBrandIcon()
                                    Spacer(modifier = Modifier.size(10.dp))
                                    Text("Duck Detector", maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            },
                            trailingContent = { DashboardTelegramAction() },
                        ),
                        NavigationShellItem(
                            title = stringResource(R.string.navigation_settings),
                            topBarTitle = stringResource(com.eltavine.duckdetector.features.settings.ui.R.string.settings_title),
                            icon = Icons.Outlined.SettingsOutline,
                            selectedIcon = Icons.Rounded.Settings,
                            pagerGesturePolicy = NavigationShellPagerGesturePolicy.RegionAware,
                        ),
                    ),
                    selectedIndex = if (destination == AppDestination.MAIN) 0 else 1,
                    onSelectedIndexChange = { index ->
                        onSelectDestination(if (index == 0) AppDestination.MAIN else AppDestination.SETTINGS)
                    },
                ) { page, padding, _, pageModifier ->
                    when (page) {
                        0 -> DashboardScreen(
                            uiState = dashboardState,
                            detectors = detectors,
                            deviceProfile = deviceProfile,
                            scaffoldPadding = padding,
                            pageModifier = pageModifier,
                        )
                        else -> SettingsScreen(
                            uiState = settingsState,
                            consentToggles = consentToggles,
                            onUiModeChange = onUiModeChange,
                            onUpdateChannelChange = { channel ->
                                updateViewModel.selectChannel(channel.toUpdateChannel())
                            },
                            onCheckForUpdates = updateViewModel::onSettingsUpdateAction,
                            onGitHubAccelerationChange = { enabled ->
                                scope.launch { accelerationStore.setEnabled(enabled) }
                            },
                            onOpenLicenses = openLicenses,
                            scaffoldPadding = padding,
                            pageModifier = pageModifier,
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                }
            },
            licenses = {
                OpenSourceLicensesScreen(onBack = backFromLicenses, modifier = Modifier.fillMaxSize())
            },
        )

        updateDialogPayload.value?.let { availableUpdate ->
            UpdateDialog(
                show = visibleUpdate != null,
                currentVersionName = BuildConfig.VERSION_NAME,
                update = availableUpdate,
                downloadEnabled = !isResolvingUpdateDownload,
                onDismiss = updateViewModel::dismissUpdate,
                onDismissFinished = updateDialogPayload.onDismissFinished,
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
