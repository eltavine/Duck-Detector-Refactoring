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

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.LocalTextStyle
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.settings.ui.R

@Composable
internal fun ImportantSection(modifier: Modifier = Modifier) {
    SettingsSection(title = stringResource(R.string.settings_important_title), modifier = modifier) {
        SettingsGroup {
            SettingsItem(
                headline = stringResource(R.string.settings_important_why),
                shapes = settingsItemShapes(index = 0, count = 1),
                supportingContent = {
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        listOf(
                            R.string.settings_important_intro,
                            R.string.settings_important_context,
                            R.string.settings_important_consequences,
                        ).forEach { paragraph ->
                            WrapSafeText(text = stringResource(paragraph))
                        }
                        WrapSafeText(
                            text = stringResource(R.string.settings_important_goal),
                            style = LocalTextStyle.current.copy(fontWeight = FontWeight.SemiBold),
                        )
                        WrapSafeText(text = stringResource(R.string.settings_important_evidence))
                    }
                },
            )
        }
    }
}
