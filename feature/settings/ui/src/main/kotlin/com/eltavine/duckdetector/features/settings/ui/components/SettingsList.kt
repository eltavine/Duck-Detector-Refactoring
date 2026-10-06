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

import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.material3.ListItemColors
import androidx.compose.material3.ListItemShapes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsFootnote
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsGroup
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsIconTile
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsItem
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsItemColors
import io.github.xiaotong6666.uihelper.adaptive.NativeSettingsSection
import io.github.xiaotong6666.uihelper.adaptive.adaptiveMonochromeIconColor

@Composable
internal fun SettingsSection(
    title: String,
    modifier: Modifier = Modifier,
    badge: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    NativeSettingsSection(
        title = title,
        modifier = modifier,
        badge = badge,
        materialBadgeColor = DuckTheme.palette.groupedSurface,
        materialBadgeContentColor = MaterialTheme.colorScheme.onSurface,
        materialBadgeTextStyle = MaterialTheme.typography.labelSmall,
        content = content,
    )
}

/** Rows that read as one block while uihelper owns each skin's native container semantics. */
@Composable
internal fun SettingsGroup(content: @Composable ColumnScope.() -> Unit) {
    NativeSettingsGroup(content = content)
}

@Composable
internal fun SettingsItem(
    headline: String,
    shapes: ListItemShapes,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
    enabled: Boolean = true,
    colors: ListItemColors = settingsItemColors(),
    leadingContent: (@Composable () -> Unit)? = null,
    supportingContent: (@Composable () -> Unit)? = null,
    trailingContent: (@Composable () -> Unit)? = null,
) {
    NativeSettingsItem(
        headline = headline,
        modifier = modifier,
        materialShapes = shapes,
        onClick = onClick,
        enabled = enabled,
        materialColors = colors,
        leadingContent = leadingContent,
        supportingContent = supportingContent,
        trailingContent = trailingContent,
    )
}

/** Disabled rows keep their colors: a row is disabled only while it is busy, not unavailable. */
@Composable
internal fun settingsItemColors(
    containerColor: Color = DuckTheme.palette.groupedSurface,
    contentColor: Color = MaterialTheme.colorScheme.onSurface,
    supportingColor: Color = MaterialTheme.colorScheme.onSurfaceVariant,
): ListItemColors = NativeSettingsItemColors(
    containerColor = containerColor,
    contentColor = contentColor,
    supportingColor = supportingColor,
)

@Composable
internal fun SettingsIconTile(
    icon: ImageVector,
    tint: Color? = null,
) {
    NativeSettingsIconTile(
        icon = icon,
        materialTint = tint ?: MaterialTheme.colorScheme.onSurfaceVariant,
        miuixTint = tint ?: MaterialTheme.colorScheme.primary,
    )
}

/** About-section glyphs stay monochrome on MIUIX and retain the old Material neutral tint. */
@Composable
internal fun AboutLeadingIcon(icon: ImageVector) {
    SettingsIconTile(icon = icon, tint = aboutMiuixIconColor())
}

@Composable
internal fun aboutMiuixIconColor(): Color =
    adaptiveMonochromeIconColor(materialColor = MaterialTheme.colorScheme.onSurfaceVariant)

@Composable
internal fun SettingsIconTile(
    content: @Composable BoxScope.() -> Unit,
) {
    NativeSettingsIconTile(content = content)
}

@Composable
internal fun SettingsFootnote(
    text: String,
    modifier: Modifier = Modifier,
    title: String? = null,
    icon: ImageVector? = null,
) {
    NativeSettingsFootnote(
        text = text,
        modifier = modifier,
        title = title,
        icon = icon,
        materialTitleStyle = MaterialTheme.typography.labelMedium,
        materialBodyStyle = MaterialTheme.typography.bodySmall,
    )
}
