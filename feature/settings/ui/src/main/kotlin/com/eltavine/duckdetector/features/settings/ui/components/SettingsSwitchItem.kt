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

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsItemShapes

@Composable
internal fun SettingsSwitchItem(
    headline: String,
    summary: String,
    icon: ImageVector,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    SettingsItem(
        headline = headline,
        shapes = NativeSettingsItemShapes(),
        modifier = modifier.semantics {
            role = Role.Switch
            toggleableState = if (checked) ToggleableState.On else ToggleableState.Off
        },
        onClick = { onCheckedChange(!checked) },
        leadingContent = { SettingsIconTile(icon = icon) },
        supportingContent = { WrapSafeText(text = summary) },
        trailingContent = {
            Switch(
                checked = checked,
                onCheckedChange = null,
                thumbContent = if (checked) {
                    {
                        Icon(
                            imageVector = Icons.Rounded.Check,
                            contentDescription = null,
                            modifier = Modifier.size(SwitchDefaults.IconSize),
                        )
                    }
                } else {
                    null
                },
            )
        },
    )
}
