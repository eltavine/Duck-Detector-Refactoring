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
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ProgressIndicatorDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.detector.ConsentId
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import com.eltavine.duckdetector.features.dashboard.ui.DashboardTopBarBrandIcon
import com.eltavine.duckdetector.notifications.ScanNotificationPermissionState
import com.eltavine.duckdetector.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.sdk.PackageVisibility
import com.eltavine.duckdetector.startup.StartupHeroGlyph
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveCircularProgressIndicator
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.adaptiveVerticalScrollFeedback
import io.github.xiaotong6666.uihelper.adaptive.adaptiveBodyStyle
import io.github.xiaotong6666.uihelper.adaptive.adaptiveContainerContentColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSecondaryTextColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveTitleStyle
import io.github.xiaotong6666.uihelper.material.scaffold.ExpressiveScaffold
import io.github.xiaotong6666.uihelper.material.scaffold.expressiveTopAppBarColors
import io.github.xiaotong6666.uihelper.material.scaffold.materialTopBarEdgeToEdgeInsets
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator as MiuixLinearProgressIndicator
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold as MiuixScaffold
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.theme.MiuixTheme

@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
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
    showUiStyleSelection: Boolean,
    onUiModeChange: (UiMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    val uiMode = LocalUiMode.current
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

    AdaptiveContent(
        miuix = {
            val scrollState = rememberScrollState()
            val scrollBehavior = MiuixScrollBehavior()
            MiuixScaffold(
                modifier = modifier.fillMaxSize(),
                containerColor = MiuixTheme.colorScheme.surface,
                contentWindowInsets = WindowInsets.systemBars
                    .add(WindowInsets.displayCutout)
                    .only(WindowInsetsSides.Horizontal),
                topBar = {
                    StartupMiuixTopBar(
                        title = stringResource(R.string.startup_review_label),
                        scrollBehavior = scrollBehavior,
                    )
                },
            ) { innerPadding ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .nestedScroll(scrollBehavior.nestedScrollConnection)
                        .adaptiveVerticalScrollFeedback()
                        .verticalScroll(scrollState, overscrollEffect = null),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Column(
                        modifier = Modifier
                            .widthIn(max = 560.dp)
                            .fillMaxWidth()
                            .padding(innerPadding)
                            .padding(horizontal = 12.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        StartupPolicyHero(
                            gateState = gateState,
                            resolvedCount = resolvedCount,
                            totalCount = totalCount,
                            progress = progress,
                        )
                        if (showUiStyleSelection) {
                            StartupUiStyleCard(
                                uiMode = uiMode,
                                onUiModeChange = onUiModeChange,
                            )
                        }
                        if (gateState == StartupGateState.LOADING) {
                            LoadingPolicyCard()
                        } else {
                            cards.forEach { card -> StartupPolicyCard(card = card) }
                        }
                    }
                }
            }
        },
        material = {
            val scrollState = rememberScrollState()
            val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
            ExpressiveScaffold(
                modifier = modifier
                    .fillMaxSize()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                topBar = {
                    LargeFlexibleTopAppBar(
                        title = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                DashboardTopBarBrandIcon()
                                Spacer(modifier = Modifier.size(10.dp))
                                Text(text = stringResource(R.string.startup_review_label))
                            }
                        },
                        colors = expressiveTopAppBarColors(),
                        scrollBehavior = scrollBehavior,
                        windowInsets = materialTopBarEdgeToEdgeInsets(),
                    )
                },
            ) { innerPadding ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scrollState),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Column(
                        modifier = Modifier
                            .widthIn(max = 560.dp)
                            .fillMaxWidth()
                            .padding(innerPadding)
                            .padding(horizontal = 16.dp, vertical = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        StartupPolicyHero(
                            gateState = gateState,
                            resolvedCount = resolvedCount,
                            totalCount = totalCount,
                            progress = progress,
                        )
                        if (showUiStyleSelection) {
                            StartupUiStyleCard(
                                uiMode = uiMode,
                                onUiModeChange = onUiModeChange,
                            )
                        }
                        if (gateState == StartupGateState.LOADING) {
                            LoadingPolicyCard()
                        } else {
                            cards.forEach { card -> StartupPolicyCard(card = card) }
                        }
                    }
                }
            }
        },
    )
}

@Composable
private fun StartupPolicyHero(
    gateState: StartupGateState,
    resolvedCount: Int,
    totalCount: Int,
    progress: Float,
) {
    val loading = gateState == StartupGateState.LOADING
    AdaptiveContent(
        miuix = {
            MiuixCard(
                modifier = Modifier.fillMaxWidth(),
                insideMargin = PaddingValues(0.dp),
            ) {
                BasicComponent(
                    title = stringResource(
                        if (loading) R.string.startup_preparing_title else R.string.startup_before_scan_title,
                    ),
                    summary = stringResource(
                        if (loading) R.string.startup_loading_detail else R.string.startup_intro_detail,
                    ),
                    startAction = {
                        DuckIcon(
                            imageVector = Icons.Rounded.VerifiedUser,
                            contentDescription = null,
                            modifier = Modifier.padding(end = 12.dp).size(22.dp),
                            tint = MiuixTheme.colorScheme.onSurface,
                        )
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .semantics { heading() },
                )
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    ResolutionProgress(
                        progress = progress,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    MiuixText(
                        text = if (loading) {
                            stringResource(R.string.startup_loading_state)
                        } else {
                            stringResource(R.string.startup_progress_resolved, resolvedCount, totalCount)
                        },
                        style = MiuixTheme.textStyles.footnote1,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
            }
        },
        material = {
            val colorScheme = MaterialTheme.colorScheme
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp, bottom = 12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                StartupHeroGlyph(icon = Icons.Rounded.VerifiedUser)
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
        },
    )
}
