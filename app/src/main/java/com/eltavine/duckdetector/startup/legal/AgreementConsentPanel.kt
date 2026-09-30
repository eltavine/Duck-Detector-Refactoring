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

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsBottomHeight
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Calculate
import androidx.compose.material.icons.outlined.VerticalAlignBottom
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material3.Button
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.designsystem.components.DuckButtonDefaults
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.DetectorHairline

/**
 * The bar pinned below the agreement: the countdown, the arithmetic check and the button that
 * becomes active once the reader has scrolled to the end, waited and answered.
 *
 * [onContentHeightChanged] reports the bar's height without the navigation bar or keyboard
 * beneath it, which is the part of the document the bar covers.
 */
@Composable
internal fun AgreementConsentPanel(
    countdown: Int,
    timerComplete: Boolean,
    num1: Int,
    num2: Int,
    isAddition: Boolean,
    answerState: TextFieldState,
    mathCorrect: Boolean,
    isScrolledToBottom: Boolean,
    canProceed: Boolean,
    buttonScale: Float,
    onAgree: () -> Unit,
    onContentHeightChanged: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val palette = DuckTheme.palette
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(palette.groupedSurface),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .onSizeChanged { size -> onContentHeightChanged(size.height) },
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            DetectorHairline()
            Column(
                modifier = Modifier
                    .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
                    .widthIn(max = 560.dp)
                    .fillMaxWidth()
                    .padding(start = 20.dp, end = 20.dp, top = 14.dp, bottom = 12.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(color = palette.groupedInset, shape = ShapeTokens.CornerLarge),
                ) {
                    ConditionRow(
                        icon = Icons.Rounded.Timer,
                        text = if (timerComplete) {
                            stringResource(R.string.timer_elapsed)
                        } else {
                            stringResource(R.string.timer_waiting, countdown)
                        },
                        isComplete = timerComplete,
                    )
                    DetectorHairline(startInset = ConditionTextInset)
                    ConditionRow(
                        icon = Icons.Outlined.VerticalAlignBottom,
                        text = if (isScrolledToBottom) {
                            stringResource(R.string.fully_reviewed)
                        } else {
                            stringResource(R.string.scroll_to_bottom)
                        },
                        isComplete = isScrolledToBottom,
                    )
                    DetectorHairline(startInset = ConditionTextInset)
                    ConditionRow(
                        icon = Icons.Outlined.Calculate,
                        text = "$num1 ${if (isAddition) "+" else "-"} $num2 =",
                        isComplete = mathCorrect,
                    ) {
                        AgreementAnswerField(state = answerState, isCorrect = mathCorrect)
                    }
                }

                AgreeButton(
                    canProceed = canProceed,
                    buttonScale = buttonScale,
                    onAgree = onAgree,
                )

                Text(
                    text = stringResource(R.string.agreement_acknowledgement),
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
        Spacer(modifier = Modifier.windowInsetsBottomHeight(WindowInsets.safeDrawing))
    }
}

@Composable
private fun AgreeButton(
    canProceed: Boolean,
    buttonScale: Float,
    onAgree: () -> Unit,
) {
    Button(
        onClick = {
            if (canProceed) {
                onAgree()
            }
        },
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 54.dp)
            .graphicsLayer {
                scaleX = buttonScale
                scaleY = buttonScale
            },
        enabled = canProceed,
        colors = DuckButtonDefaults.filledColors(),
        contentPadding = DuckButtonDefaults.LargeContentPadding,
    ) {
        AnimatedContent(
            targetState = canProceed,
            transitionSpec = {
                fadeIn(MotionTokens.FadeInOut) togetherWith fadeOut(MotionTokens.FadeInOut)
            },
            label = "agreement_button_label",
        ) { ready ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (ready) {
                    DuckIcon(
                        imageVector = Icons.Rounded.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                    )
                }
                Text(
                    text = if (ready) {
                        stringResource(R.string.i_agree_continue)
                    } else {
                        stringResource(R.string.complete_all_conditions)
                    },
                    style = DuckTypography.Headline,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
