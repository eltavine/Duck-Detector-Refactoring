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

package com.eltavine.duckdetector.ui.shell

import com.eltavine.duckdetector.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.sdk.PackageVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppShellStateTest {

    @Test
    fun `null prefs stay in loading gate`() {
        val gateState = resolveStartupGateState(
            consentDecisionsLoaded = false,
            notificationPrefs = null,
            notificationPermissionState = ScanNotificationPermissionState(
                notificationsGranted = false,
                liveUpdatesSupported = true,
                liveUpdatesGranted = false,
            ),
            packageVisibilityLoaded = false,
            packageVisibility = PackageVisibility.Scope.UNKNOWN,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.LOADING, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `missing notification permission requires notification decision`() {
        val gateState = resolveStartupGateState(
            consentDecisionsLoaded = true,
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
            packageVisibility = PackageVisibility.Scope.FULL,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `missing promoted access requires live update decision`() {
        val gateState = resolveStartupGateState(
            consentDecisionsLoaded = true,
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
            packageVisibility = PackageVisibility.Scope.FULL,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `detector consents do not block detector creation once their decisions load`() {
        val gateState = resolveStartupGateState(
            consentDecisionsLoaded = true,
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
            packageVisibility = PackageVisibility.Scope.FULL,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.READY, gateState)
        assertTrue(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `restricted package visibility requires explicit acknowledgement`() {
        val gateState = resolveStartupGateState(
            consentDecisionsLoaded = true,
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
            packageVisibility = PackageVisibility.Scope.RESTRICTED,
            packageVisibilityReviewAcknowledged = false,
        )

        assertEquals(StartupGateState.REQUIRES_POLICY_REVIEW, gateState)
        assertFalse(shouldCreateDetectorViewModels(gateState))
    }

    @Test
    fun `answered prefs unlock detector creation`() {
        val gateState = resolveStartupGateState(
            consentDecisionsLoaded = true,
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
            packageVisibility = PackageVisibility.Scope.FULL,
            packageVisibilityReviewAcknowledged = true,
        )

        assertEquals(StartupGateState.READY, gateState)
        assertTrue(shouldCreateDetectorViewModels(gateState))
    }

}
