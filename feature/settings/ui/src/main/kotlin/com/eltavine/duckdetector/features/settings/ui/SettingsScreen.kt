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

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.overscroll
import androidx.compose.foundation.rememberOverscrollEffect
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState
import com.eltavine.duckdetector.features.settings.ui.components.AboutSection
import com.eltavine.duckdetector.features.settings.ui.components.ConsentSettingItem
import com.eltavine.duckdetector.features.settings.ui.components.ContributorNameWordmark
import com.eltavine.duckdetector.features.settings.ui.components.ContributorsSection
import com.eltavine.duckdetector.features.settings.ui.components.SettingsGroup
import com.eltavine.duckdetector.features.settings.ui.components.SettingsSection
import com.eltavine.duckdetector.features.settings.ui.components.SettingsSwitchItem
import com.eltavine.duckdetector.features.settings.ui.components.UiStyleSettingItem
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.mode.UiMode

@Composable
fun SettingsScreen(
    uiState: SettingsUiState,
    consentToggles: List<ConsentToggle>,
    onCheckForUpdates: () -> Unit,
    onGitHubAccelerationChange: (Boolean) -> Unit,
    onUiModeChange: (UiMode) -> Unit,
    onOpenLicenses: () -> Unit,
    modifier: Modifier = Modifier,
    scaffoldPadding: PaddingValues,
    pageModifier: Modifier = Modifier,
) {
    AdaptiveContent(
        miuix = {
            SettingsMiuixPage(
                uiState = uiState,
                consentToggles = consentToggles,
                onCheckForUpdates = onCheckForUpdates,
                onGitHubAccelerationChange = onGitHubAccelerationChange,
                onUiModeChange = onUiModeChange,
                onOpenLicenses = onOpenLicenses,
                scaffoldPadding = scaffoldPadding,
                pageModifier = pageModifier,
            )
        },
        material = {
            SettingsPage(
                uiState = uiState,
                consentToggles = consentToggles,
                onCheckForUpdates = onCheckForUpdates,
                onGitHubAccelerationChange = onGitHubAccelerationChange,
                onUiModeChange = onUiModeChange,
                onOpenLicenses = onOpenLicenses,
                modifier = modifier,
                scaffoldPadding = scaffoldPadding,
            )
        },
    )
}

@Composable
private fun SettingsPage(
    uiState: SettingsUiState,
    consentToggles: List<ConsentToggle>,
    onCheckForUpdates: () -> Unit,
    onGitHubAccelerationChange: (Boolean) -> Unit,
    onUiModeChange: (UiMode) -> Unit,
    onOpenLicenses: () -> Unit,
    modifier: Modifier = Modifier,
    scaffoldPadding: PaddingValues,
) {
    val materialOverscrollEffect = rememberOverscrollEffect()
    Box(
        modifier = modifier
            .fillMaxSize()
            .background(DuckTheme.palette.groupedBackground)
            .overscroll(materialOverscrollEffect),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(scaffoldPadding)
                .verticalScroll(rememberScrollState(), overscrollEffect = materialOverscrollEffect)
                .padding(horizontal = 16.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                modifier = Modifier
                    .widthIn(max = 720.dp)
                    .fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(24.dp),
            ) {
                SettingsSection(title = stringResource(R.string.settings_section_appearance)) {
                    val styleItems = listOf(
                        stringResource(R.string.settings_style_miuix),
                        stringResource(R.string.settings_style_material),
                    )
                    SettingsGroup {
                        UiStyleSettingItem(
                            title = stringResource(R.string.settings_ui_style_title),
                            description = stringResource(R.string.settings_ui_style_description),
                            items = styleItems,
                            selectedIndex = 1,
                            onItemSelected = { index ->
                                onUiModeChange(if (index == 0) UiMode.Miuix else UiMode.Material)
                            },
                        )
                    }
                }

                if (consentToggles.isNotEmpty()) {
                    SettingsSection(title = stringResource(R.string.settings_section_detection)) {
                        consentToggles.forEach { toggle -> ConsentSettingItem(toggle = toggle) }
                    }
                }

                SettingsSection(title = stringResource(R.string.settings_section_network)) {
                    SettingsSwitchItem(
                        headline = stringResource(R.string.github_acceleration_title),
                        summary = stringResource(R.string.github_acceleration_summary),
                        icon = Icons.Rounded.Speed,
                        checked = uiState.gitHubAccelerationEnabled,
                        onCheckedChange = onGitHubAccelerationChange,
                    )
                }

                AboutSection(
                    uiState = uiState,
                    onCheckForUpdates = onCheckForUpdates,
                    onOpenLicenses = onOpenLicenses,
                )

                ContributorsSection()
                ContributorNameWordmark()
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}
