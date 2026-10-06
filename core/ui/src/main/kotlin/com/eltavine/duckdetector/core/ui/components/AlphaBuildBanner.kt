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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.core.ui.R
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** A ribbon across the top end corner that marks every screen of an alpha build. */
@Composable
public fun AlphaBuildBanner(
    modifier: Modifier = Modifier,
    isAlphaBuild: Boolean = LocalAppBuildInfo.current.isAlphaVersion,
) {
    if (!isAlphaBuild) {
        return
    }

    val isDarkTheme = isSystemInDarkTheme()
    val bannerColor = adaptiveValue(
        material = if (isDarkTheme) Color(0xFFFFB74D) else Color(0xFFD84315),
        miuix = MiuixTheme.colorScheme.primary,
    )
    val textColor = adaptiveValue(
        material = if (isDarkTheme) Color.Black else Color.White,
        miuix = MiuixTheme.colorScheme.onPrimary,
    )

    Box(
        modifier = modifier.fillMaxSize(),
    ) {
        Box(
            modifier = Modifier
                .align(Alignment.TopEnd)
                .offset(x = 32.dp, y = 28.dp)
                .rotate(45f)
                .background(bannerColor)
                .width(140.dp)
                .heightIn(min = 24.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = stringResource(R.string.alpha_banner),
                color = textColor,
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
            )
        }
    }
}
