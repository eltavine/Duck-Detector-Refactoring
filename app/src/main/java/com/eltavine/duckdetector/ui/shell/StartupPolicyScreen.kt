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

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CloudSync
import androidx.compose.material.icons.rounded.Inventory2
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.Update
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.ui.theme.ShapeTokens

data class StartupPackageVisibilityState(
    val visibility: InstalledPackageVisibility,
    val visiblePackageCount: Int,
    val suspiciouslyLowInventory: Boolean,
)

@Composable
fun StartupPolicyScreen(
    gateState: StartupGateState,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
    teePrefs: TeeNetworkPrefs?,
    packageVisibilityState: StartupPackageVisibilityState?,
    packageVisibilityReviewAcknowledged: Boolean,
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
    onOpenLiveUpdateSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
    onAllowCrlNetwork: () -> Unit,
    onUseLocalCrlOnly: () -> Unit,
    onAcknowledgePackageVisibility: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cards = if (
        gateState == StartupGateState.LOADING ||
        notificationPrefs == null ||
        teePrefs == null ||
        packageVisibilityState == null
    ) {
        emptyList()
    } else {
        listOf(
            notificationPolicyCard(
                notificationPrefs = notificationPrefs,
                permissionState = notificationPermissionState,
                onAllowNotifications = onAllowNotifications,
                onSkipNotifications = onSkipNotifications,
            ),
            liveUpdatePolicyCard(
                notificationPrefs = notificationPrefs,
                permissionState = notificationPermissionState,
                onOpenLiveUpdateSettings = onOpenLiveUpdateSettings,
                onUseRegularNotifications = onUseRegularNotifications,
            ),
            crlPolicyCard(
                teePrefs = teePrefs,
                onAllowCrlNetwork = onAllowCrlNetwork,
                onUseLocalCrlOnly = onUseLocalCrlOnly,
            ),
            packageManagerPolicyCard(
                packageVisibilityState = packageVisibilityState,
                packageVisibilityReviewAcknowledged = packageVisibilityReviewAcknowledged,
                onAcknowledgePackageVisibility = onAcknowledgePackageVisibility,
            ),
        )
    }
    val resolvedCount = cards.count { !it.requiresAction }
    val totalCount = cards.size.coerceAtLeast(1)
    val progress = resolvedCount.toFloat() / totalCount.toFloat()

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            StartupPolicyHero(
                gateState = gateState,
                resolvedCount = resolvedCount,
                totalCount = totalCount,
                progress = progress,
            )

            if (gateState == StartupGateState.LOADING) {
                LoadingPolicyCard()
            } else {
                cards.forEach { card ->
                    StartupPolicyCard(card = card)
                }
            }
        }
    }
}

@Composable
private fun StartupPolicyHero(
    gateState: StartupGateState,
    resolvedCount: Int,
    totalCount: Int,
    progress: Float,
) {
    Surface(
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(60.dp)
                        .background(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = CircleShape,
                        ),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VerifiedUser,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.size(28.dp),
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    WrapSafeText(
                        text = stringResource(R.string.startup_review_label),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    WrapSafeText(
                        text = if (gateState == StartupGateState.LOADING) {
                            stringResource(R.string.startup_preparing_title)
                        } else {
                            stringResource(R.string.startup_before_scan_title)
                        },
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = if (gateState == StartupGateState.LOADING) {
                    stringResource(R.string.startup_loading_detail)
                } else {
                    stringResource(R.string.startup_intro_detail)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            LinearProgressIndicator(
                progress = { progress },
                modifier = Modifier.fillMaxWidth(),
            )

            WrapSafeText(
                text = if (gateState == StartupGateState.LOADING) {
                    stringResource(R.string.startup_loading_state)
                } else {
                    stringResource(
                        R.string.startup_progress_resolved,
                        resolvedCount,
                        totalCount,
                    )
                },
                style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Medium),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LoadingPolicyCard() {
    Surface(
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(28.dp),
                strokeWidth = 3.dp,
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                WrapSafeText(
                    text = stringResource(R.string.startup_loading_dependencies_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = stringResource(R.string.startup_loading_dependencies_detail),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun StartupPolicyCard(
    card: StartupPolicyCardUi,
) {
    val colors = card.tone.colors()
    Surface(
        shape = ShapeTokens.CornerExtraLarge,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(color = colors.container, shape = ShapeTokens.CornerLarge),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = card.icon,
                        contentDescription = null,
                        tint = colors.content,
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        WrapSafeText(
                            text = card.title,
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.weight(1f),
                        )
                        StatusBadge(
                            label = card.statusLabel,
                            containerColor = colors.container,
                            contentColor = colors.content,
                        )
                    }

                    WrapSafeText(
                        text = card.headline,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = card.detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (card.primaryActionLabel != null || card.secondaryActionLabel != null) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (card.secondaryActionLabel != null && card.onSecondaryAction != null) {
                        OutlinedButton(onClick = card.onSecondaryAction) {
                            WrapSafeText(
                                text = card.secondaryActionLabel,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                        Spacer(modifier = Modifier.width(10.dp))
                    }

                    if (card.primaryActionLabel != null && card.onPrimaryAction != null) {
                        FilledTonalButton(onClick = card.onPrimaryAction) {
                            WrapSafeText(
                                text = card.primaryActionLabel,
                                style = MaterialTheme.typography.labelLarge,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusBadge(
    label: String,
    containerColor: Color,
    contentColor: Color,
) {
    Surface(
        color = containerColor,
        shape = ShapeTokens.CornerFull,
    ) {
        WrapSafeText(
            text = label,
            style = MaterialTheme.typography.labelMedium,
            color = contentColor,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
        )
    }
}

@Composable
private fun notificationPolicyCard(
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
private fun liveUpdatePolicyCard(
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

@Composable
private fun crlPolicyCard(
    teePrefs: TeeNetworkPrefs,
    onAllowCrlNetwork: () -> Unit,
    onUseLocalCrlOnly: () -> Unit,
): StartupPolicyCardUi {
    return if (!teePrefs.consentAsked) {
        StartupPolicyCardUi(
            icon = Icons.Rounded.CloudSync,
            title = stringResource(R.string.startup_crl_title),
            statusLabel = stringResource(R.string.startup_status_action_required),
            headline = stringResource(R.string.startup_crl_prompt_headline),
            detail = stringResource(R.string.startup_crl_prompt_detail),
            tone = StartupPolicyTone.REQUIRED,
            requiresAction = true,
            primaryActionLabel = stringResource(R.string.startup_crl_allow_network),
            secondaryActionLabel = stringResource(R.string.startup_crl_local_only),
            onPrimaryAction = onAllowCrlNetwork,
            onSecondaryAction = onUseLocalCrlOnly,
        )
    } else if (teePrefs.consentGranted) {
        StartupPolicyCardUi(
            icon = Icons.Rounded.CloudSync,
            title = stringResource(R.string.startup_crl_title),
            statusLabel = stringResource(R.string.startup_status_ready),
            headline = stringResource(R.string.startup_crl_ready_headline),
            detail = stringResource(R.string.startup_crl_ready_detail),
            tone = StartupPolicyTone.READY,
            requiresAction = false,
        )
    } else {
        StartupPolicyCardUi(
            icon = Icons.Rounded.CloudSync,
            title = stringResource(R.string.startup_crl_title),
            statusLabel = stringResource(R.string.startup_status_local),
            headline = stringResource(R.string.startup_crl_local_headline),
            detail = stringResource(R.string.startup_crl_local_detail),
            tone = StartupPolicyTone.ACKNOWLEDGED,
            requiresAction = false,
        )
    }
}

@Composable
private fun packageManagerPolicyCard(
    packageVisibilityState: StartupPackageVisibilityState,
    packageVisibilityReviewAcknowledged: Boolean,
    onAcknowledgePackageVisibility: () -> Unit,
): StartupPolicyCardUi {
    return when {
        packageVisibilityState.visibility == InstalledPackageVisibility.RESTRICTED &&
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

        packageVisibilityState.visibility == InstalledPackageVisibility.RESTRICTED -> StartupPolicyCardUi(
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

        packageVisibilityState.suspiciouslyLowInventory -> StartupPolicyCardUi(
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

private data class StartupPolicyCardUi(
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

private enum class StartupPolicyTone {
    REQUIRED,
    READY,
    ACKNOWLEDGED,
    SUPPORT,
}

private data class StartupPolicyColors(
    val container: Color,
    val content: Color,
)

private fun StartupPolicyTone.colors(): StartupPolicyColors {
    return when (this) {
        StartupPolicyTone.REQUIRED -> StartupPolicyColors(
            container = Color(0xFFFDE7D9),
            content = Color(0xFF9A3412),
        )

        StartupPolicyTone.READY -> StartupPolicyColors(
            container = Color(0xFFDDF4E4),
            content = Color(0xFF166534),
        )

        StartupPolicyTone.ACKNOWLEDGED -> StartupPolicyColors(
            container = Color(0xFFE8ECF8),
            content = Color(0xFF334155),
        )

        StartupPolicyTone.SUPPORT -> StartupPolicyColors(
            container = Color(0xFFE9E7FF),
            content = Color(0xFF5B43B5),
        )
    }
}
