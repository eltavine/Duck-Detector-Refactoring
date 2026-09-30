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

package com.eltavine.duckdetector.features.settings.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DisplaySettings
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.features.settings.presentation.model.SettingsUiState
import com.eltavine.duckdetector.features.settings.ui.components.AboutSection
import com.eltavine.duckdetector.features.settings.ui.components.ContributorNameWordmark
import com.eltavine.duckdetector.features.settings.ui.components.ContributorsSection
import com.eltavine.duckdetector.features.settings.ui.components.SettingsGroup
import com.eltavine.duckdetector.features.settings.ui.components.SettingsSection
import io.github.xiaotong6666.uihelper.adaptive.SettingsDropdownItem
import io.github.xiaotong6666.uihelper.adaptive.SettingsToggleItem
import io.github.xiaotong6666.uihelper.adaptive.adaptiveVerticalScrollFeedback
import io.github.xiaotong6666.uihelper.mode.UiMode

/** Native MIUIX page: the navigation shell provides the collapsing top bar and bottom bar. */
@Composable
internal fun SettingsMiuixPage(
    uiState: SettingsUiState,
    consentToggles: List<ConsentToggle>,
    onCheckForUpdates: () -> Unit,
    onGitHubAccelerationChange: (Boolean) -> Unit,
    onUiModeChange: (UiMode) -> Unit,
    onOpenLicenses: () -> Unit,
    scaffoldPadding: PaddingValues,
    pageModifier: Modifier,
) {
    val direction = LocalLayoutDirection.current
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            // Keep this modifier ordering so overscroll owns the elastic top-edge gesture first,
            // then the top-bar nested-scroll connection observes the
            // remaining content scroll. This prevents the rebound leg from collapsing the title.
            .adaptiveVerticalScrollFeedback()
            .then(pageModifier),
        overscrollEffect = null,
        verticalArrangement = Arrangement.spacedBy(6.dp),
        contentPadding = PaddingValues(
            start = scaffoldPadding.calculateStartPadding(direction) + 12.dp,
            top = scaffoldPadding.calculateTopPadding() + 12.dp,
            end = scaffoldPadding.calculateEndPadding(direction) + 12.dp,
            bottom = scaffoldPadding.calculateBottomPadding() + 24.dp,
        ),
    ) {
        item(key = "appearance") {
            SettingsSection(title = stringResource(R.string.settings_section_appearance)) {
                SettingsGroup {
                    SettingsDropdownItem(
                        title = stringResource(R.string.settings_ui_style_title),
                        description = stringResource(R.string.settings_ui_style_description),
                        items = listOf(
                            stringResource(R.string.settings_style_miuix),
                            stringResource(R.string.settings_style_material),
                        ),
                        selectedIndex = 0,
                        icon = Icons.Rounded.DisplaySettings,
                        onItemSelected = { onUiModeChange(if (it == 0) UiMode.Miuix else UiMode.Material) },
                    )
                }
            }
        }
        if (consentToggles.isNotEmpty()) {
            item(key = "detection-options") {
                SettingsSection(title = stringResource(R.string.settings_section_detection)) {
                    SettingsGroup {
                        consentToggles.forEach { toggle ->
                            SettingsToggleItem(
                                checked = toggle.checked,
                                title = stringResource(toggle.setting.title),
                                description = stringResource(toggle.setting.summary),
                                icon = toggle.setting.icon,
                                onToggle = { toggle.onCheckedChange(!toggle.checked) },
                            )
                        }
                    }
                }
            }
        }
        item(key = "network") {
            SettingsSection(title = stringResource(R.string.settings_section_network)) {
                SettingsGroup {
                    SettingsToggleItem(
                        checked = uiState.gitHubAccelerationEnabled,
                        title = stringResource(R.string.github_acceleration_title),
                        description = stringResource(R.string.github_acceleration_summary),
                        icon = Icons.Rounded.Speed,
                        onToggle = { onGitHubAccelerationChange(!uiState.gitHubAccelerationEnabled) },
                    )
                }
            }
        }
        item(key = "about") {
            AboutSection(
                uiState = uiState,
                onCheckForUpdates = onCheckForUpdates,
                onOpenLicenses = onOpenLicenses,
            )
        }
        item(key = "contributors") { ContributorsSection(modifier = Modifier.fillMaxWidth()) }
        item(key = "wordmark") { ContributorNameWordmark() }
    }
}
