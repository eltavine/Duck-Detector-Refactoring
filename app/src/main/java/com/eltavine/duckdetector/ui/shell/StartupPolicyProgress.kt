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

package com.eltavine.duckdetector.ui.shell

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ProgressIndicatorDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveCircularProgressIndicator
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.adaptiveBodyStyle
import io.github.xiaotong6666.uihelper.adaptive.adaptiveContainerContentColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSecondaryTextColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveTitleStyle
import top.yukonga.miuix.kmp.basic.LinearProgressIndicator as MiuixLinearProgressIndicator

/** A thin bar that fills as startup cards are resolved. */
@Composable
internal fun ResolutionProgress(
    progress: Float,
    modifier: Modifier = Modifier,
) {
    val fraction by animateFloatAsState(
        targetValue = progress.coerceIn(0f, 1f),
        animationSpec = ProgressIndicatorDefaults.ProgressAnimationSpec,
        label = "startupProgress",
    )
    AdaptiveContent(
        miuix = {
            MiuixLinearProgressIndicator(
                progress = fraction,
                modifier = modifier,
            )
        },
        material = {
            LinearProgressIndicator(
                progress = { fraction },
                modifier = modifier.height(6.dp),
                color = MaterialTheme.colorScheme.primary,
                trackColor = DuckTheme.palette.separator,
                strokeCap = StrokeCap.Round,
                gapSize = 0.dp,
                drawStopIndicator = {},
            )
        },
    )
}

@Composable
internal fun LoadingPolicyCard() {
    AdaptiveContent(
        miuix = {
            DuckPanel(
                contentPadding = PaddingValues(horizontal = 18.dp, vertical = 18.dp),
            ) {
                LoadingPolicyCardContent()
            }
        },
        material = {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        color = DuckTheme.palette.groupedSurface,
                        shape = MaterialTheme.shapes.large,
                    )
                    .padding(horizontal = 18.dp, vertical = 18.dp),
            ) {
                LoadingPolicyCardContent()
            }
        },
    )
}

@Composable
private fun LoadingPolicyCardContent() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        AdaptiveCircularProgressIndicator(size = 24.dp, materialStrokeWidth = 2.5.dp)
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = stringResource(R.string.startup_loading_dependencies_title),
                style = adaptiveTitleStyle(DuckTypography.Headline),
                color = adaptiveContainerContentColor(),
            )
            WrapSafeText(
                text = stringResource(R.string.startup_loading_dependencies_detail),
                style = adaptiveBodyStyle(DuckTypography.Footnote),
                color = adaptiveSecondaryTextColor(),
            )
        }
    }
}
