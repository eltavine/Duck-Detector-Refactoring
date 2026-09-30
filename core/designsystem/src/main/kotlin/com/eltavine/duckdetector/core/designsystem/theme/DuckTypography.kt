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

package com.eltavine.duckdetector.core.designsystem.theme

import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.LineBreak
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Text styles for grouped screens, stepped like Apple's text styles: a large title for the page,
 * a headline for each container, then callout, footnote and caption for the text inside it.
 */
public object DuckTypography {
    /** Native MIUIX page title, with the existing Google Sans title retained for Material. */
    public val PageTitle: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.title1 else MaterialTheme.typography.headlineLarge

    public val StatusHeadline: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.title3 else MaterialTheme.typography.headlineSmall

    public val PanelTitle: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.headline1.copy(fontWeight = FontWeight.Medium)
        } else {
            MaterialTheme.typography.titleMedium
        }

    public val PanelBody: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.body1
        } else {
            MaterialTheme.typography.bodyMedium
        }

    public val PanelSupporting: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.body2 else MaterialTheme.typography.bodyMedium

    public val PanelCaption: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.footnote1 else MaterialTheme.typography.labelMedium

    public val SectionTitle: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.headline1 else MaterialTheme.typography.titleMedium

    public val DetailLabel: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.footnote1
        } else {
            MaterialTheme.typography.bodySmall
        }

    public val DetailValue: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.body1.copy(lineHeight = 22.sp)
        } else {
            MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium)
        }

    public val ActionLabel: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.button
        } else {
            MaterialTheme.typography.labelLargeEmphasized
        }

    public val FindingEyebrow: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.footnote1 else FootnoteEmphasized

    public val LoadingTitle: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.title3 else PanelTitle

    public val LoadingSupporting: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.body2 else PanelSupporting

    public val ReportAction: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.body2.copy(fontWeight = FontWeight.Medium)
        } else {
            MaterialTheme.typography.labelLargeEmphasized
        }

    public val ReportMeta: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.footnote1 else MaterialTheme.typography.bodySmall

    public val MetricNumeral: TextStyle
        @Composable @ReadOnlyComposable
        get() = if (LocalUiMode.current == UiMode.Miuix) {
            MiuixTheme.textStyles.title2.copy(fontFeatureSettings = "tnum", fontWeight = FontWeight.Medium)
        } else {
            Numeral
        }

    public val LargeTitle: TextStyle = heading(34.sp, 41.sp, FontWeight.Bold, (-0.4).sp)
    public val Title1: TextStyle = heading(28.sp, 34.sp, FontWeight.Bold, (-0.3).sp)
    public val Title2: TextStyle = heading(22.sp, 28.sp, FontWeight.Bold, (-0.2).sp)
    public val Title3: TextStyle = heading(20.sp, 25.sp, FontWeight.SemiBold, (-0.1).sp)
    public val Headline: TextStyle = heading(17.sp, 22.sp, FontWeight.SemiBold, (-0.1).sp)
    public val Body: TextStyle = paragraph(16.sp, 22.sp, FontWeight.Normal, 0.sp)
    public val Callout: TextStyle = paragraph(15.sp, 20.sp, FontWeight.Normal, 0.sp)
    public val CalloutEmphasized: TextStyle = paragraph(15.sp, 20.sp, FontWeight.Medium, 0.sp)
    public val Footnote: TextStyle = paragraph(13.sp, 18.sp, FontWeight.Normal, 0.05.sp)
    public val FootnoteEmphasized: TextStyle = paragraph(13.sp, 18.sp, FontWeight.SemiBold, 0.05.sp)
    public val Caption: TextStyle = paragraph(12.sp, 16.sp, FontWeight.Medium, 0.1.sp)

    /** Figures of equal width, so counts that change during a scan do not shift their neighbours. */
    public val Numeral: TextStyle = heading(24.sp, 28.sp, FontWeight.SemiBold, 0.sp)
        .copy(fontFeatureSettings = "tnum")
}

private fun heading(size: TextUnit, lineHeight: TextUnit, weight: FontWeight, tracking: TextUnit) =
    wrapAwareStyle(style(size, lineHeight, weight, tracking), LineBreak.Heading)

private fun paragraph(size: TextUnit, lineHeight: TextUnit, weight: FontWeight, tracking: TextUnit) =
    wrapAwareStyle(style(size, lineHeight, weight, tracking), LineBreak.Paragraph)

private fun style(size: TextUnit, lineHeight: TextUnit, weight: FontWeight, tracking: TextUnit) =
    TextStyle(
        fontFamily = GoogleSansFlexFamily,
        fontWeight = weight,
        fontSize = size,
        lineHeight = lineHeight,
        letterSpacing = tracking,
    )
