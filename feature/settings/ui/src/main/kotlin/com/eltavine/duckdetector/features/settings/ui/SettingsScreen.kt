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

package com.eltavine.duckdetector.features.settings.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.AnimatedContentTransitionScope.SlideDirection
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.animation.core.spring
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.StatusBarProtection
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUpdateChannel
import com.eltavine.duckdetector.features.settings.ui.components.AboutSection
import com.eltavine.duckdetector.features.settings.ui.components.ConsentSettingItem
import com.eltavine.duckdetector.features.settings.ui.components.ContributorNameWordmark
import com.eltavine.duckdetector.features.settings.ui.components.ContributorsSection
import com.eltavine.duckdetector.features.settings.ui.components.SettingsSection
import com.eltavine.duckdetector.features.settings.ui.components.SettingsSwitchItem
import com.eltavine.duckdetector.features.settings.ui.licenses.OpenSourceLicensesScreen

private const val SettingsPageKey = "settings"

private val PageSlide = spring(
    stiffness = Spring.StiffnessMediumLow,
    visibilityThreshold = IntOffset.VisibilityThreshold,
)

@Composable
fun SettingsScreen(
    uiState: SettingsUiState,
    consentToggles: List<ConsentToggle>,
    onUpdateChannelChange: (SettingsUpdateChannel) -> Unit,
    onCheckForUpdates: () -> Unit,
    onGitHubAccelerationChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    var showingLicenses by rememberSaveable { mutableStateOf(false) }
    // The settings page leaves composition while the licenses page shows; this keeps its scroll
    // position and expanded rows for the way back.
    val pageStates = rememberSaveableStateHolder()

    AnimatedContent(
        targetState = showingLicenses,
        modifier = modifier
            .fillMaxSize()
            .background(DuckTheme.palette.groupedBackground),
        transitionSpec = { pageTransition() },
        label = "settingsPage",
    ) { licenses ->
        if (licenses) {
            OpenSourceLicensesScreen(
                onBack = { showingLicenses = false },
                modifier = Modifier.fillMaxSize(),
            )
        } else {
            pageStates.SaveableStateProvider(SettingsPageKey) {
                SettingsPage(
                    uiState = uiState,
                    consentToggles = consentToggles,
                    onUpdateChannelChange = onUpdateChannelChange,
                    onCheckForUpdates = onCheckForUpdates,
                    onGitHubAccelerationChange = onGitHubAccelerationChange,
                    onOpenLicenses = { showingLicenses = true },
                )
            }
        }
    }
}

/** Opening the licenses page moves both pages towards the start edge; going back reverses it. */
private fun AnimatedContentTransitionScope<Boolean>.pageTransition(): ContentTransform {
    val towards = if (targetState) SlideDirection.Start else SlideDirection.End
    val enter = slideIntoContainer(towards, PageSlide) { it / 5 } + fadeIn(MotionTokens.FadeInOut)
    val exit = slideOutOfContainer(towards, PageSlide) { it / 5 } + fadeOut(MotionTokens.FadeInOut)
    return enter togetherWith exit
}

@Composable
private fun SettingsPage(
    uiState: SettingsUiState,
    consentToggles: List<ConsentToggle>,
    onUpdateChannelChange: (SettingsUpdateChannel) -> Unit,
    onCheckForUpdates: () -> Unit,
    onGitHubAccelerationChange: (Boolean) -> Unit,
    onOpenLicenses: () -> Unit,
) {
    Box(
        modifier = Modifier
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
                    .widthIn(max = 720.dp)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(24.dp),
            ) {
                WrapSafeText(
                    text = stringResource(R.string.settings_title),
                    modifier = Modifier.semantics { heading() },
                    style = DuckTypography.LargeTitle,
                    color = MaterialTheme.colorScheme.onSurface,
                )

                if (consentToggles.isNotEmpty()) {
                    SettingsSection(title = stringResource(R.string.settings_section_detection)) {
                        consentToggles.forEach { toggle ->
                            ConsentSettingItem(toggle = toggle)
                        }
                    }
                }

                SettingsSection(title = stringResource(R.string.settings_section_network)) {
                    SettingsSwitchItem(
                        headline = stringResource(R.string.github_acceleration_title),
                        summary = stringResource(R.string.github_acceleration_summary),
                        footer = stringResource(R.string.github_acceleration_footer),
                        icon = Icons.Rounded.Speed,
                        checked = uiState.gitHubAccelerationEnabled,
                        onCheckedChange = onGitHubAccelerationChange,
                    )
                }

                AboutSection(
                    uiState = uiState,
                    onUpdateChannelChange = onUpdateChannelChange,
                    onCheckForUpdates = onCheckForUpdates,
                    onOpenLicenses = onOpenLicenses,
                )

                ContributorsSection()
                ContributorNameWordmark()
                Spacer(modifier = Modifier.height(96.dp))
            }
        }

        StatusBarProtection(modifier = Modifier.align(Alignment.TopCenter))
    }
}
