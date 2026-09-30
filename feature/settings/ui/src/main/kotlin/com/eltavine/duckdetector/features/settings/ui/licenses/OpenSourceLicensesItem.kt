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

package com.eltavine.duckdetector.features.settings.ui.licenses

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material3.ListItemShapes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.settings.ui.R
import com.eltavine.duckdetector.features.settings.ui.components.AboutLeadingIcon
import com.eltavine.duckdetector.features.settings.ui.components.SettingsItem
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.SettingsNavigationItem

@Composable
internal fun OpenSourceLicensesItem(
    shapes: ListItemShapes,
    onClick: () -> Unit,
) {
    val title = stringResource(R.string.licenses_entry_title)
    val description = stringResource(R.string.licenses_entry_subtitle)
    AdaptiveContent(
        miuix = {
            SettingsNavigationItem(
                title = title,
                description = description,
                icon = Icons.Rounded.Description,
                onClick = onClick,
            )
        },
        material = {
            SettingsItem(
                headline = title,
                shapes = shapes,
                onClick = onClick,
                leadingContent = { AboutLeadingIcon(icon = Icons.Rounded.Description) },
                supportingContent = { WrapSafeText(text = description) },
                trailingContent = {
                    DuckIcon(
                        imageVector = Icons.AutoMirrored.Rounded.KeyboardArrowRight,
                        contentDescription = null,
                    )
                },
            )
        },
    )
}
