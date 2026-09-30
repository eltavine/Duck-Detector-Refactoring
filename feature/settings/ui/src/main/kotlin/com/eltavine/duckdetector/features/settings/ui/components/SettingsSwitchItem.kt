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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsToggleItem

@Composable
internal fun SettingsSwitchItem(
    headline: String,
    summary: String,
    icon: ImageVector,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val shapes = settingsItemShapes(index = 0, count = 1)
    Column(
        modifier = modifier.fillMaxWidth(),
    ) {
        SettingsGroup {
            NativeSettingsToggleItem(
                checked = checked,
                title = headline,
                description = summary,
                icon = icon,
                onCheckedChange = onCheckedChange,
                materialShapes = shapes,
                materialColors = settingsItemColors(),
            )
        }
    }
}
