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

import android.os.Build
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Inventory2
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.Update
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.ui.detector.ConsentPrompt
import com.eltavine.duckdetector.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.sdk.PackageVisibility
@Composable
internal fun notificationPolicyCard(
    notificationPrefs: ScanNotificationPrefs,
    permissionState: ScanNotificationPermissionState,
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
): StartupPolicyCardUi {
    return when {
        permissionState.notificationsGranted -> StartupPolicyCardUi(
            icon = Icons.Rounded.NotificationsActive,
            title = stringResource(R.string.startup_notifications_title),
            statusLabel = stringResource(R.string.startup_status_ready),
            headline = stringResource(R.string.startup_notifications_ready_headline),
            detail = stringResource(R.string.startup_notifications_ready_detail),
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )

        !notificationPrefs.notificationsPrompted -> StartupPolicyCardUi(
            icon = Icons.Rounded.NotificationsActive,
            title = stringResource(R.string.startup_notifications_title),
            statusLabel = stringResource(R.string.startup_status_action_required),
            headline = stringResource(R.string.startup_notifications_prompt_headline),
            detail = if (Build.VERSION.SDK_INT >= 33) {
                stringResource(
                    R.string.startup_notifications_prompt_detail_api33,
                    Build.VERSION.SDK_INT,
                )
            } else {
                stringResource(R.string.startup_notifications_prompt_detail_legacy)
            },
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = stringResource(R.string.startup_notifications_allow),
            secondaryActionLabel = stringResource(R.string.startup_notifications_skip),
            onPrimaryAction = onAllowNotifications,
            onSecondaryAction = onSkipNotifications,
        )

        else -> StartupPolicyCardUi(
            icon = Icons.Rounded.NotificationsActive,
            title = stringResource(R.string.startup_notifications_title),
            statusLabel = stringResource(R.string.startup_status_skipped),
            headline = stringResource(R.string.startup_notifications_skipped_headline),
            detail = stringResource(R.string.startup_notifications_skipped_detail),
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

@Composable
internal fun liveUpdatePolicyCard(
    notificationPrefs: ScanNotificationPrefs,
    permissionState: ScanNotificationPermissionState,
    onOpenLiveUpdateSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
): StartupPolicyCardUi {
    return when {
        !permissionState.liveUpdatesSupported -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = stringResource(R.string.startup_live_update_title),
            statusLabel = stringResource(R.string.startup_status_unsupported),
            headline = stringResource(R.string.startup_live_update_unsupported_headline),
            detail = stringResource(R.string.startup_live_update_unsupported_detail),
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        !permissionState.notificationsGranted -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = stringResource(R.string.startup_live_update_title),
            statusLabel = stringResource(R.string.startup_status_waiting),
            headline = stringResource(R.string.startup_live_update_waiting_headline),
            detail = stringResource(R.string.startup_live_update_waiting_detail),
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        permissionState.liveUpdatesGranted -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = stringResource(R.string.startup_live_update_title),
            statusLabel = stringResource(R.string.startup_status_ready),
            headline = stringResource(R.string.startup_live_update_ready_headline),
            detail = stringResource(R.string.startup_live_update_ready_detail),
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )

        !notificationPrefs.liveUpdatesPrompted -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = stringResource(R.string.startup_live_update_title),
            statusLabel = stringResource(R.string.startup_status_action_required),
            headline = stringResource(R.string.startup_live_update_prompt_headline),
            detail = stringResource(R.string.startup_live_update_prompt_detail),
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = stringResource(R.string.startup_live_update_open_settings),
            secondaryActionLabel = stringResource(R.string.startup_live_update_use_regular),
            onPrimaryAction = onOpenLiveUpdateSettings,
            onSecondaryAction = onUseRegularNotifications,
        )

        else -> StartupPolicyCardUi(
            icon = Icons.Rounded.Update,
            title = stringResource(R.string.startup_live_update_title),
            statusLabel = stringResource(R.string.startup_status_regular),
            headline = stringResource(R.string.startup_live_update_regular_headline),
            detail = stringResource(R.string.startup_live_update_regular_detail),
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

/** A detector consent's card. Consents are optional, so no decision is ever required to continue. */
@Composable
internal fun consentPolicyCard(
    prompt: ConsentPrompt,
    decision: ConsentDecision,
    onDecide: (granted: Boolean) -> Unit,
): StartupPolicyCardUi {
    return when (decision) {
        ConsentDecision.UNDECIDED -> StartupPolicyCardUi(
            icon = prompt.icon,
            title = stringResource(prompt.title),
            statusLabel = stringResource(R.string.startup_status_optional),
            headline = stringResource(prompt.headline),
            detail = stringResource(prompt.detail),
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
            primaryActionLabel = stringResource(prompt.allowLabel),
            secondaryActionLabel = stringResource(prompt.declineLabel),
            onPrimaryAction = { onDecide(true) },
            onSecondaryAction = { onDecide(false) },
        )

        ConsentDecision.GRANTED -> StartupPolicyCardUi(
            icon = prompt.icon,
            title = stringResource(prompt.title),
            statusLabel = stringResource(R.string.startup_status_ready),
            headline = stringResource(prompt.grantedHeadline),
            detail = stringResource(prompt.grantedDetail),
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )

        ConsentDecision.DECLINED -> StartupPolicyCardUi(
            icon = prompt.icon,
            title = stringResource(prompt.title),
            statusLabel = stringResource(prompt.declinedStatus),
            headline = stringResource(prompt.declinedHeadline),
            detail = stringResource(prompt.declinedDetail),
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

@Composable
internal fun packageManagerPolicyCard(
    packageVisibilityState: PackageVisibility,
    packageVisibilityReviewAcknowledged: Boolean,
    onAcknowledgePackageVisibility: () -> Unit,
): StartupPolicyCardUi {
    return when {
        packageVisibilityState.scope == PackageVisibility.Scope.RESTRICTED &&
                !packageVisibilityReviewAcknowledged -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = stringResource(R.string.startup_package_manager_title),
            statusLabel = stringResource(R.string.startup_status_action_required),
            headline = stringResource(R.string.startup_package_restricted_headline),
            detail = stringResource(
                R.string.startup_package_restricted_detail,
                packageVisibilityState.visiblePackageCount,
            ),
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = stringResource(R.string.startup_package_continue_anyway),
            onPrimaryAction = onAcknowledgePackageVisibility,
        )

        packageVisibilityState.scope == PackageVisibility.Scope.RESTRICTED -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = stringResource(R.string.startup_package_manager_title),
            statusLabel = stringResource(R.string.startup_status_acknowledged),
            headline = stringResource(R.string.startup_package_ack_headline),
            detail = stringResource(
                R.string.startup_package_ack_detail,
                packageVisibilityState.visiblePackageCount,
            ),
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )

        packageVisibilityState.scope == PackageVisibility.Scope.UNKNOWN -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = stringResource(R.string.startup_package_manager_title),
            statusLabel = stringResource(R.string.startup_status_unsupported),
            headline = stringResource(R.string.startup_package_unavailable_headline),
            detail = stringResource(R.string.startup_package_unavailable_detail),
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        packageVisibilityState.suspiciouslyLow -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = stringResource(R.string.startup_package_manager_title),
            statusLabel = stringResource(R.string.startup_status_review_later),
            headline = stringResource(R.string.startup_package_low_inventory_headline),
            detail = stringResource(
                R.string.startup_package_low_inventory_detail,
                packageVisibilityState.visiblePackageCount,
            ),
            tone = StartupPolicyTone.SUPPORT,
            requiresAction = false,
        )

        else -> StartupPolicyCardUi(
            icon = Icons.Rounded.Inventory2,
            title = stringResource(R.string.startup_package_manager_title),
            statusLabel = stringResource(R.string.startup_status_ready),
            headline = stringResource(R.string.startup_package_ready_headline),
            detail = stringResource(
                R.string.startup_package_ready_detail,
                packageVisibilityState.visiblePackageCount,
            ),
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )
    }
}

internal data class StartupPolicyCardUi(
    val icon: ImageVector,
    val title: String,
    val statusLabel: String,
    val headline: String,
    val detail: String,
    val tone: StartupPolicyTone,
    val requiresAction: Boolean,
    val primaryActionLabel: String? = null,
    val secondaryActionLabel: String? = null,
    val onPrimaryAction: (() -> Unit)? = null,
    val onSecondaryAction: (() -> Unit)? = null,
)

internal enum class StartupPolicyTone {
    REQUIRED,
    READY,
    ACKNOWLEDGED,
    SUPPORT,
}
