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

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.eltavine.duckdetector.notifications.ScanNotificationPermissions
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationConsentStore
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.packagevisibility.preferences.PackageVisibilityReviewPrefs
import com.eltavine.duckdetector.packagevisibility.preferences.PackageVisibilityReviewStore
import com.eltavine.duckdetector.sdk.DuckDetector
import com.eltavine.duckdetector.sdk.PackageVisibility
import com.eltavine.duckdetector.startup.legal.AgreementAcceptancePrefs
import com.eltavine.duckdetector.startup.legal.AgreementAcceptanceStore
import com.eltavine.duckdetector.startup.legal.AgreementScreen
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.ui.components.AlphaBuildBanner
import com.eltavine.duckdetector.core.ui.components.ScreenshotWatermarkOverlay
import com.eltavine.duckdetector.ui.shell.AppDestination
import com.eltavine.duckdetector.ui.shell.StartupPolicyScreen
import com.eltavine.duckdetector.ui.shell.combineConsentDecisions
import com.eltavine.duckdetector.ui.shell.resolveStartupGateState
import com.eltavine.duckdetector.ui.shell.shouldCreateDetectorViewModels
import kotlinx.coroutines.launch
import io.github.xiaotong6666.uihelper.mode.UiMode

@Composable
fun DuckDetectorApp(onUiModeChange: (UiMode) -> Unit) {
    val blacklistMatch = remember { DeviceBlacklist.matchCurrentDevice() }
    if (blacklistMatch != null) {
        Surface {
            BlockedDeviceScreen(
                match = blacklistMatch,
                modifier = Modifier.fillMaxSize(),
            )
        }
        return
    }

    val context = LocalContext.current
    val appContext = context.applicationContext
    val agreementStore = remember(appContext) { AgreementAcceptanceStore.getInstance(appContext) }
    val notificationConsentStore = remember(appContext) {
        ScanNotificationConsentStore.getInstance(appContext)
    }
    val packageVisibilityReviewStore = remember(appContext) {
        PackageVisibilityReviewStore.getInstance(appContext)
    }
    val agreementPrefs by produceState<AgreementAcceptancePrefs?>(
        initialValue = null,
        key1 = agreementStore,
    ) {
        agreementStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val agreementAccepted = agreementPrefs?.accepted == true
    val consentDecisions by produceState<Map<ConsentId, ConsentDecision>?>(
        initialValue = null,
        key1 = appContext,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        combineConsentDecisions(
            DetectorFeatures.consentCards.associate { it.consent.id to it.consent.decisions(appContext) },
        ).collect { decisions ->
            value = decisions
        }
    }
    val notificationPrefs by produceState<ScanNotificationPrefs?>(
        initialValue = null,
        key1 = notificationConsentStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        notificationConsentStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val packageVisibilityReviewPrefs by produceState<PackageVisibilityReviewPrefs?>(
        initialValue = null,
        key1 = packageVisibilityReviewStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        packageVisibilityReviewStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val packageVisibilityState by produceState<PackageVisibility?>(
        initialValue = null,
        key1 = appContext,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        value = DuckDetector.packageVisibility(appContext)
    }
    var notificationPermissionState by remember {
        mutableStateOf(ScanNotificationPermissions.read(appContext))
    }
    val gateState = remember(
        consentDecisions,
        notificationPrefs,
        notificationPermissionState,
        packageVisibilityState,
        packageVisibilityReviewPrefs,
    ) {
        resolveStartupGateState(
            consentDecisionsLoaded = consentDecisions != null,
            notificationPrefs = notificationPrefs,
            notificationPermissionState = notificationPermissionState,
            packageVisibilityLoaded = packageVisibilityState != null &&
                    packageVisibilityReviewPrefs != null,
            packageVisibility = packageVisibilityState?.scope
                ?: PackageVisibility.Scope.UNKNOWN,
            packageVisibilityReviewAcknowledged =
                packageVisibilityReviewPrefs?.restrictedInventoryAcknowledged == true,
        )
    }
    val startupPoliciesReady = shouldCreateDetectorViewModels(gateState)
    var destination by rememberSaveable { mutableStateOf(AppDestination.MAIN) }
    val scope = rememberCoroutineScope()
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) {
        notificationPermissionState = ScanNotificationPermissions.read(appContext)
        scope.launch {
            notificationConsentStore.markNotificationsPrompted()
        }
    }
    val liveUpdateSettingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) {
        notificationPermissionState = ScanNotificationPermissions.read(appContext)
        if (notificationPermissionState.liveUpdatesGranted) {
            scope.launch {
                notificationConsentStore.markLiveUpdatesPrompted()
            }
        }
    }

    LaunchedEffect(notificationPrefs, notificationPermissionState) {
        val prefs = notificationPrefs ?: return@LaunchedEffect
        if (notificationPermissionState.notificationsGranted && !prefs.notificationsPrompted) {
            notificationConsentStore.markNotificationsPrompted()
        }
        if (notificationPermissionState.liveUpdatesGranted && !prefs.liveUpdatesPrompted) {
            notificationConsentStore.markLiveUpdatesPrompted()
        }
    }

    Surface {
        Box(modifier = Modifier.fillMaxSize()) {
            when {
                agreementPrefs == null -> {
                    StartupBootstrapLoadingScreen(modifier = Modifier.fillMaxSize())
                }

                !agreementAccepted -> {
                    AgreementScreen(
                        onAgree = {
                            scope.launch {
                                agreementStore.accept()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }

                startupPoliciesReady -> {
                    AppReadyShell(
                        destination = destination,
                        onSelectDestination = { selected -> destination = selected },
                        onUiModeChange = onUiModeChange,
                        consentDecisions = requireNotNull(consentDecisions),
                        notificationPermissionState = notificationPermissionState,
                    )
                }

                else -> {
                    StartupPolicyScreen(
                        gateState = gateState,
                        notificationPrefs = notificationPrefs,
                        notificationPermissionState = notificationPermissionState,
                        consentCards = DetectorFeatures.consentCards,
                        consentDecisions = consentDecisions,
                        packageVisibilityState = packageVisibilityState,
                        packageVisibilityReviewAcknowledged =
                            packageVisibilityReviewPrefs?.restrictedInventoryAcknowledged == true,
                        onAllowNotifications = {
                            if (Build.VERSION.SDK_INT >= 33) {
                                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                            } else {
                                scope.launch {
                                    notificationConsentStore.markNotificationsPrompted()
                                }
                            }
                        },
                        onSkipNotifications = {
                            scope.launch {
                                notificationConsentStore.markNotificationsPrompted()
                            }
                        },
                        onOpenLiveUpdateSettings = {
                            val intent = ScanNotificationPermissions
                                .appNotificationPromotionSettingsIntent(appContext)
                            val canOpenSettings =
                                intent.resolveActivity(appContext.packageManager) != null
                            if (canOpenSettings) {
                                liveUpdateSettingsLauncher.launch(intent)
                            } else {
                                scope.launch {
                                    notificationConsentStore.markLiveUpdatesPrompted()
                                }
                            }
                        },
                        onUseRegularNotifications = {
                            scope.launch {
                                notificationConsentStore.markLiveUpdatesPrompted()
                            }
                        },
                        onDecideConsent = { consentCard, granted ->
                            scope.launch {
                                consentCard.consent.decide(appContext, granted)
                            }
                        },
                        onAcknowledgePackageVisibility = {
                            scope.launch {
                                packageVisibilityReviewStore.acknowledgeRestrictedInventory()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }
            }

            ScreenshotWatermarkOverlay()

            if (agreementAccepted && startupPoliciesReady) {
                AlphaBuildBanner()
            }
        }
    }
}
