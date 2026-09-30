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

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ProgressIndicatorDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.designsystem.components.StatusBarProtection
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.sdk.PackageVisibility
import com.eltavine.duckdetector.startup.StartupHeroGlyph
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveCircularProgressIndicator
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.adaptiveBodyStyle
import io.github.xiaotong6666.uihelper.adaptive.adaptiveContainerContentColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSecondaryTextColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveTitleStyle

@Composable
internal fun StartupPolicyScreen(
    gateState: StartupGateState,
    notificationPrefs: ScanNotificationPrefs?,
    notificationPermissionState: ScanNotificationPermissionState,
    consentCards: List<DetectorConsentCard>,
    consentDecisions: Map<ConsentId, ConsentDecision>?,
    packageVisibilityState: PackageVisibility?,
    packageVisibilityReviewAcknowledged: Boolean,
    onAllowNotifications: () -> Unit,
    onSkipNotifications: () -> Unit,
    onOpenLiveUpdateSettings: () -> Unit,
    onUseRegularNotifications: () -> Unit,
    onDecideConsent: (DetectorConsentCard, granted: Boolean) -> Unit,
    onAcknowledgePackageVisibility: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val cards = if (
        gateState == StartupGateState.LOADING ||
        notificationPrefs == null ||
        consentDecisions == null ||
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
        ) + consentCards.map { consentCard ->
            consentPolicyCard(
                prompt = consentCard.card.prompt,
                decision = consentDecisions.getValue(consentCard.consent.id),
                onDecide = { granted -> onDecideConsent(consentCard, granted) },
            )
        } + listOf(
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
            .background(DuckTheme.palette.groupedBackground),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .windowInsetsPadding(WindowInsets.safeDrawing)
                .padding(horizontal = 20.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                modifier = Modifier
                    .widthIn(max = 560.dp)
                    .fillMaxWidth(),
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

        StatusBarProtection(modifier = Modifier.align(Alignment.TopCenter))
    }
}

@Composable
private fun StartupPolicyHero(
    gateState: StartupGateState,
    resolvedCount: Int,
    totalCount: Int,
    progress: Float,
) {
    val loading = gateState == StartupGateState.LOADING
    val colorScheme = MaterialTheme.colorScheme
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 20.dp, bottom = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        StartupHeroGlyph(icon = Icons.Rounded.VerifiedUser)

        WrapSafeText(
            text = stringResource(R.string.startup_review_label),
            modifier = Modifier.padding(top = 8.dp),
            style = DuckTypography.FootnoteEmphasized,
            color = colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        WrapSafeText(
            text = stringResource(
                if (loading) R.string.startup_preparing_title else R.string.startup_before_scan_title,
            ),
            modifier = Modifier.semantics { heading() },
            style = DuckTypography.LargeTitle,
            color = colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        WrapSafeText(
            text = stringResource(
                if (loading) R.string.startup_loading_detail else R.string.startup_intro_detail,
            ),
            style = DuckTypography.Callout,
            color = colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        ResolutionProgress(
            progress = progress,
            modifier = Modifier
                .padding(top = 10.dp)
                .widthIn(max = 280.dp)
                .fillMaxWidth(),
        )
        WrapSafeText(
            text = if (loading) {
                stringResource(R.string.startup_loading_state)
            } else {
                stringResource(R.string.startup_progress_resolved, resolvedCount, totalCount)
            },
            style = DuckTypography.Footnote,
            color = colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

/** A thin bar that fills as startup cards are resolved. */
@Composable
private fun ResolutionProgress(
    progress: Float,
    modifier: Modifier = Modifier,
) {
    val fraction by animateFloatAsState(
        targetValue = progress.coerceIn(0f, 1f),
        animationSpec = ProgressIndicatorDefaults.ProgressAnimationSpec,
        label = "startupProgress",
    )
    LinearProgressIndicator(
        progress = { fraction },
        modifier = modifier.height(6.dp),
        color = MaterialTheme.colorScheme.primary,
        trackColor = DuckTheme.palette.separator,
        strokeCap = StrokeCap.Round,
        gapSize = 0.dp,
        drawStopIndicator = {},
    )
}

@Composable
private fun LoadingPolicyCard() {
    AdaptiveContent(
        miuix = {
            // DuckPanel uses the native MIUIX Card: surfaceContainer and squircle corners.
            DuckPanel(
                contentPadding = PaddingValues(horizontal = 18.dp, vertical = 18.dp),
            ) {
                LoadingPolicyCardContent()
            }
        },
        material = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        color = DuckTheme.palette.groupedSurface,
                        shape = MaterialTheme.shapes.large,
                    )
                    .padding(horizontal = 18.dp, vertical = 18.dp),
            ) {
                LoadingPolicyCardContent()
            }
        },
    )
}

@Composable
private fun LoadingPolicyCardContent() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        AdaptiveCircularProgressIndicator(size = 24.dp, materialStrokeWidth = 2.5.dp)
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = stringResource(R.string.startup_loading_dependencies_title),
                style = adaptiveTitleStyle(DuckTypography.Headline),
                color = adaptiveContainerContentColor(),
            )
            WrapSafeText(
                text = stringResource(R.string.startup_loading_dependencies_detail),
                style = adaptiveBodyStyle(DuckTypography.Footnote),
                color = adaptiveSecondaryTextColor(),
            )
        }
    }
}
