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

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.Hyphens
import androidx.compose.ui.text.style.LineBreak
import androidx.compose.ui.unit.sp
import com.eltavine.duckdetector.core.designsystem.R

// A single wght-axis variable font. Every entry sets its wght value explicitly: Font(resId, weight)
// binds to an overload that attaches no variation settings, so each weight would render as the
// font's default Regular instance, and never be synthesized either, since it claims that weight.
internal val GoogleSansFlexFamily: FontFamily = FontFamily(
    (400..900 step 100).map { weight ->
        Font(
            resId = R.font.googlesansflex_variable,
            weight = FontWeight(weight),
            variationSettings = FontVariation.Settings(FontVariation.weight(weight)),
        )
    },
)

internal fun wrapAwareStyle(
    style: TextStyle,
    lineBreak: LineBreak,
) = style.copy(
    lineBreak = lineBreak,
    hyphens = Hyphens.Auto,
)

internal val Typography: Typography = Typography(
    displayLarge = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 57.sp,
            lineHeight = 64.sp,
            letterSpacing = (-0.25).sp,
        ), LineBreak.Heading
    ),
    displayMedium = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 45.sp,
            lineHeight = 52.sp,
            letterSpacing = 0.sp,
        ), LineBreak.Heading
    ),
    displaySmall = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Bold,
            fontSize = 36.sp,
            lineHeight = 44.sp,
            letterSpacing = 0.sp,
        ), LineBreak.Heading
    ),
    headlineLarge = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = 32.sp,
            lineHeight = 40.sp,
            letterSpacing = 0.sp,
        ), LineBreak.Heading
    ),
    headlineMedium = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = 28.sp,
            lineHeight = 36.sp,
            letterSpacing = 0.sp,
        ), LineBreak.Heading
    ),
    headlineSmall = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = 24.sp,
            lineHeight = 32.sp,
            letterSpacing = 0.sp,
        ), LineBreak.Heading
    ),
    titleLarge = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = 22.sp,
            lineHeight = 28.sp,
            letterSpacing = 0.sp,
        ), LineBreak.Heading
    ),
    titleMedium = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 16.sp,
            lineHeight = 24.sp,
            letterSpacing = 0.15.sp,
        ), LineBreak.Heading
    ),
    titleSmall = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            letterSpacing = 0.1.sp,
        ), LineBreak.Paragraph
    ),
    bodyLarge = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Normal,
            fontSize = 16.sp,
            lineHeight = 24.sp,
            letterSpacing = 0.5.sp,
        ), LineBreak.Paragraph
    ),
    bodyMedium = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Normal,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            letterSpacing = 0.25.sp,
        ), LineBreak.Paragraph
    ),
    bodySmall = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Normal,
            fontSize = 12.sp,
            lineHeight = 16.sp,
            letterSpacing = 0.4.sp,
        ), LineBreak.Paragraph
    ),
    labelLarge = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 14.sp,
            lineHeight = 20.sp,
            letterSpacing = 0.1.sp,
        ), LineBreak.Paragraph
    ),
    labelMedium = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 12.sp,
            lineHeight = 16.sp,
            letterSpacing = 0.5.sp,
        ), LineBreak.Paragraph
    ),
    labelSmall = wrapAwareStyle(
        TextStyle(
            fontFamily = GoogleSansFlexFamily,
            fontWeight = FontWeight.Medium,
            fontSize = 11.sp,
            lineHeight = 16.sp,
            letterSpacing = 0.5.sp,
        ), LineBreak.Paragraph
    ),
)

/**
 * Keep the Material skin on the platform-default typography baseline. Duck's Google Sans Flex
 * family is intentionally limited to the legacy/custom skin so Material Expressive list rows keep
 * the expected metrics and density.
 */
internal val ExpressiveTypography: Typography = Typography(
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp,
        letterSpacing = 0.5.sp,
    ),
)
