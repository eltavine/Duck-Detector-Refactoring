/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs

enum class AppDestination {
    MAIN,
    SETTINGS,
}

enum class StartupGateState {
    LOADING,
    REQUIRES_POLICY_REVIEW,
    READY,
}

fun resolveStartupGateState(
    teePrefs: TeeNetworkPrefs?,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
    packageVisibilityLoaded: Boolean,
    packageVisibility: InstalledPackageVisibility,
    packageVisibilityReviewAcknowledged: Boolean,
): StartupGateState {
    return when {
        teePrefs == null || notificationPrefs == null || !packageVisibilityLoaded ->
            StartupGateState.LOADING

        !notificationPrefs.notificationsPrompted &&
                !notificationPermissionState.notificationsGranted ->
            StartupGateState.REQUIRES_POLICY_REVIEW

        notificationPermissionState.notificationsGranted &&
                notificationPermissionState.liveUpdatesSupported &&
                !notificationPermissionState.liveUpdatesGranted &&
                !notificationPrefs.liveUpdatesPrompted ->
            StartupGateState.REQUIRES_POLICY_REVIEW

        !teePrefs.consentAsked -> StartupGateState.REQUIRES_POLICY_REVIEW
        packageVisibility == InstalledPackageVisibility.RESTRICTED &&
                !packageVisibilityReviewAcknowledged ->
            StartupGateState.REQUIRES_POLICY_REVIEW

        else -> StartupGateState.READY
    }
}

fun shouldCreateDetectorViewModels(gateState: StartupGateState): Boolean {
    return gateState == StartupGateState.READY
}
