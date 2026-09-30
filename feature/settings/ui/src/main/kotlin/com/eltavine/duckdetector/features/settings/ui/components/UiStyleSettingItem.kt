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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DisplaySettings
import androidx.compose.runtime.Composable
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsDropdownItem

/** Duck supplies project tokens; uihelper owns the native dropdown widget family. */
@Composable
internal fun UiStyleSettingItem(
    title: String,
    description: String,
    items: List<String>,
    selectedIndex: Int,
    onItemSelected: (Int) -> Unit,
) {
    NativeSettingsDropdownItem(
        title = title,
        description = description,
        items = items,
        selectedIndex = selectedIndex,
        icon = Icons.Rounded.DisplaySettings,
        onItemSelected = onItemSelected,
        materialShapes = settingsItemShapes(index = 0, count = 1),
        materialColors = settingsItemColors(),
    )
}
