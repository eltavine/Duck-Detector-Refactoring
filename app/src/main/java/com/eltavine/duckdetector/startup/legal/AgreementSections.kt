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

package com.eltavine.duckdetector.startup.legal

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.ContinuousCornerShape
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens

private val SectionIconShape = ContinuousCornerShape(10.dp)

@Composable
internal fun AgreementSection(
    icon: ImageVector,
    title: String,
    content: String,
    tone: AgreementSectionTone = AgreementSectionTone.Standard,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = DuckTheme.palette.groupedSurface,
                shape = ShapeTokens.CornerExtraLargeIncreased,
            )
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .background(color = DuckTheme.palette.groupedInset, shape = SectionIconShape),
                contentAlignment = Alignment.Center,
            ) {
                DuckIcon(
                    imageVector = icon,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.onSurface,
                )
            }
            Text(
                text = title,
                modifier = Modifier
                    .weight(1f)
                    .semantics { heading() },
                style = DuckTypography.Title3,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }

        AgreementSectionContent(
            content = content,
            tone = tone,
        )
    }
}

@Composable
private fun AgreementSectionContent(
    content: String,
    tone: AgreementSectionTone,
) {
    val lines = remember(content) { content.lines() }
    val firstContentIndex = remember(lines) { lines.indexOfFirst { it.isNotBlank() } }

    Column(
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        lines.forEachIndexed { index, rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
            } else {
                val lineStyle = when {
                    index == firstContentIndex && tone == AgreementSectionTone.Warning ->
                        AgreementLineStyle.Callout

                    NumberedHeadingRegex.matches(line) ->
                        AgreementLineStyle.SectionHeading

                    else -> AgreementLineStyle.Body
                }
                AgreementStyledLine(
                    text = line,
                    lineStyle = lineStyle,
                    tone = tone,
                )
            }
        }
    }
}

@Composable
private fun AgreementStyledLine(
    text: String,
    lineStyle: AgreementLineStyle,
    tone: AgreementSectionTone,
) {
    // The warning's body keeps the full text color; weight, not color, sets headings apart.
    val bodyColor = when (tone) {
        AgreementSectionTone.Warning -> MaterialTheme.colorScheme.onSurface
        AgreementSectionTone.Notice -> MaterialTheme.colorScheme.onSurfaceVariant
        AgreementSectionTone.Standard -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    val (style, color) = when (lineStyle) {
        AgreementLineStyle.Callout,
        AgreementLineStyle.SectionHeading -> DuckTypography.Headline to MaterialTheme.colorScheme.onSurface
        AgreementLineStyle.Body -> DuckTypography.Callout to bodyColor
    }

    Text(
        text = text,
        style = style,
        color = color,
        lineHeight = style.lineHeight * 1.25,
    )
}

private val NumberedHeadingRegex = Regex("""^\d+\.\s.*""")

internal enum class AgreementSectionTone {
    Standard,
    Warning,
    Notice,
}

private enum class AgreementLineStyle {
    Callout,
    SectionHeading,
    Body,
}
