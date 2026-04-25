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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppShellStateTest {

    @Test
    fun `null prefs stay in loading gate`() {
        val gateState = resolveStartupGateState(
            teePrefs = null,
            notificationPrefs = null,
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = false,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
            packageVisibilityLoaded = false,
            packageVisibility = InstalledPackageVisibility.UNKNOWN,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.LOADING, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `missing notification permission requires notification decision`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = false,
                liveUpdatesPrompted = false,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = false,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
            packageVisibilityLoaded = true,
            packageVisibility = InstalledPackageVisibility.FULL,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `missing promoted access requires live update decision`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = false,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
            packageVisibilityLoaded = true,
            packageVisibility = InstalledPackageVisibility.FULL,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `unanswered CRL prefs still block after notification onboarding`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = false,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = true,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = true,
            ),
            packageVisibilityLoaded = true,
            packageVisibility = InstalledPackageVisibility.FULL,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `restricted package visibility requires explicit acknowledgement`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = true,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = true,
            ),
            packageVisibilityLoaded = true,
            packageVisibility = InstalledPackageVisibility.RESTRICTED,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `answered prefs unlock detector creation`() {
        val gateState = resolveStartupGateState(
            teePrefs = TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
            notificationPrefs = ScanNotificationPrefs(
                notificationsPrompted = true,
                liveUpdatesPrompted = true,
            ),
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = true,
                liveUpdatesSupported = true,
                liveUpdatesGranted = true,
            ),
            packageVisibilityLoaded = true,
            packageVisibility = InstalledPackageVisibility.FULL,
            packageVisibilityReviewAcknowledged = true,
        )

        assertEquals(StartupGateState.READY, gateState)
        assertTrue(shouldCreateDetectorViewModels(gateState))
    }
}
