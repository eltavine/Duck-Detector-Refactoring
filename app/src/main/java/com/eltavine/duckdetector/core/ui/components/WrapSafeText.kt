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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.material3.LocalTextStyle
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.TextStyle

private const val LongTokenBreakInterval = 12
private const val ZeroWidthSpace = '\u200B'

@Composable
fun WrapSafeText(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = LocalTextStyle.current,
    color: Color = Color.Unspecified,
    textAlign: TextAlign? = null,
) {
    val safeText = remember(text) { text.withWrapOpportunities() }

    Text(
        text = safeText,
        modifier = modifier,
        style = if (textAlign != null) style.copy(textAlign = textAlign) else style,
        color = color,
    )
}

private fun String.withWrapOpportunities(): String {
    if (length <= LongTokenBreakInterval) return this

    val builder = StringBuilder(length + (length / LongTokenBreakInterval))
    var uninterruptedCount = 0

    for (character in this) {
        builder.append(character)

        if (character.createsNaturalBreak()) {
            if (!character.isWhitespace()) {
                builder.append(ZeroWidthSpace)
            }
            uninterruptedCount = 0
            continue
        }

        uninterruptedCount += 1
        if (uninterruptedCount >= LongTokenBreakInterval) {
            builder.append(ZeroWidthSpace)
            uninterruptedCount = 0
        }
    }

    return builder.toString()
}

private fun Char.createsNaturalBreak(): Boolean {
    return isWhitespace() || this in setOf(
        '-',
        '_',
        '/',
        '\\',
        '.',
        ':',
        ',',
        ';',
        '|',
        '+',
        '@',
        '#'
    )
}
