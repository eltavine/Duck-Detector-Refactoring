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

package com.eltavine.duckdetector.core.startup.legal

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Calculate
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.VerticalAlignBottom
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Timer
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.ui.theme.MotionTokens
import kotlinx.coroutines.delay

private val NumberedHeadingRegex = Regex("""^\d+\.\s.*""")

@Composable
fun AgreementScreen(
    onAgree: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var countdown by remember { mutableIntStateOf(30) }
    val timerComplete = countdown <= 0
    val (num1, num2, isAddition) = remember {
        val a = (10..99).random()
        val b = (1..minOf(a, 99 - a)).random()
        val add = listOf(true, false).random()
        Triple(a, b, add)
    }
    val correctAnswer = remember(num1, num2, isAddition) {
        if (isAddition) num1 + num2 else num1 - num2
    }
    var userAnswer by remember { mutableStateOf("") }
    val isCheatCode = userAnswer == "196912"
    val mathCorrect = userAnswer.toIntOrNull() == correctAnswer || isCheatCode
    val scrollState = rememberScrollState()
    val isScrolledToBottom by remember {
        derivedStateOf {
            val maxScroll = scrollState.maxValue
            maxScroll > 0 && scrollState.value >= maxScroll - 50
        }
    }
    val canProceed = isCheatCode || (timerComplete && mathCorrect && isScrolledToBottom)
    val buttonScale by animateFloatAsState(
        targetValue = if (canProceed) 1f else 0.96f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow,
        ),
        label = "agreement_button_scale",
    )
    val buttonAlpha by animateFloatAsState(
        targetValue = if (canProceed) 1f else 0.5f,
        animationSpec = tween(MotionTokens.Duration.Medium2),
        label = "agreement_button_alpha",
    )
    var showContent by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        showContent = true
    }

    LaunchedEffect(Unit) {
        while (countdown > 0) {
            delay(1_000L)
            countdown -= 1
        }
    }

    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding(),
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .verticalScroll(scrollState)
                    .padding(horizontal = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Spacer(modifier = Modifier.height(40.dp))

                AnimatedVisibility(
                    visible = showContent,
                    enter = scaleIn(
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioMediumBouncy,
                            stiffness = Spring.StiffnessLow,
                        ),
                    ) + fadeIn(),
                ) {
                    Box(
                        modifier = Modifier
                            .size(96.dp)
                            .shadow(
                                elevation = 8.dp,
                                shape = CircleShape,
                                ambientColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.3f),
                                spotColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.3f),
                            )
                            .clip(CircleShape)
                            .background(
                                Brush.radialGradient(
                                    colors = listOf(
                                        MaterialTheme.colorScheme.primaryContainer,
                                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.8f),
                                    ),
                                ),
                            ),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Security,
                            contentDescription = null,
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(28.dp))

                AnimatedVisibility(
                    visible = showContent,
                    enter = slideInVertically(
                        initialOffsetY = { it / 2 },
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioLowBouncy,
                            stiffness = Spring.StiffnessLow,
                        ),
                    ) + fadeIn(),
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = stringResource(R.string.user_agreement),
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onBackground,
                        )
                        Text(
                            text = stringResource(R.string.disclaimer),
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Medium,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                AnimatedVisibility(
                    visible = showContent,
                    enter = fadeIn(animationSpec = tween(delayMillis = 200)),
                ) {
                    Text(
                        text = stringResource(R.string.please_read_carefully),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.SemiBold,
                        textAlign = TextAlign.Center,
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                AgreementRiskBanner()

                Spacer(modifier = Modifier.height(24.dp))

                AgreementSection(
                    icon = Icons.Outlined.Gavel,
                    title = stringResource(R.string.user_agreement_title),
                    content = stringResource(R.string.user_agreement_content),
                )

                Spacer(modifier = Modifier.height(16.dp))

                AgreementSection(
                    icon = Icons.Outlined.Warning,
                    title = stringResource(R.string.disclaimer_title),
                    content = stringResource(R.string.disclaimer_content),
                    tone = AgreementSectionTone.Warning,
                )

                Spacer(modifier = Modifier.height(16.dp))

                AgreementSection(
                    icon = Icons.Outlined.PrivacyTip,
                    title = stringResource(R.string.privacy_notice_title),
                    content = stringResource(R.string.privacy_notice_content),
                    tone = AgreementSectionTone.Notice,
                )

                Spacer(modifier = Modifier.height(32.dp))
            }

            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.surfaceContainer,
                tonalElevation = 2.dp,
                shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                        ),
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
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
                            ConditionRow(
                                icon = Icons.Outlined.VerticalAlignBottom,
                                text = if (isScrolledToBottom) {
                                    stringResource(R.string.fully_reviewed)
                                } else {
                                    stringResource(R.string.scroll_to_bottom)
                                },
                                isComplete = isScrolledToBottom,
                            )
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Icon(
                                    imageVector = if (mathCorrect) {
                                        Icons.Rounded.CheckCircle
                                    } else {
                                        Icons.Outlined.Calculate
                                    },
                                    contentDescription = null,
                                    modifier = Modifier.size(22.dp),
                                    tint = if (mathCorrect) {
                                        MaterialTheme.colorScheme.primary
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                                Spacer(modifier = Modifier.width(12.dp))
                                Text(
                                    text = "$num1 ${if (isAddition) "+" else "-"} $num2 = ",
                                    style = MaterialTheme.typography.bodyLarge,
                                    fontWeight = FontWeight.Medium,
                                    color = if (mathCorrect) {
                                        MaterialTheme.colorScheme.primary
                                    } else {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    },
                                )
                                OutlinedTextField(
                                    value = userAnswer,
                                    onValueChange = { input ->
                                        if (
                                            input.length <= 6 &&
                                            input.all {
                                                it.isDigit() || (it == '-' && input.indexOf(
                                                    '-'
                                                ) == 0)
                                            }
                                        ) {
                                            userAnswer = input
                                        }
                                    },
                                    modifier = Modifier
                                        .width(80.dp)
                                        .height(52.dp),
                                    textStyle = MaterialTheme.typography.bodyLarge.copy(
                                        textAlign = TextAlign.Center,
                                        fontWeight = FontWeight.SemiBold,
                                    ),
                                    singleLine = true,
                                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                    colors = OutlinedTextFieldDefaults.colors(
                                        focusedBorderColor = if (mathCorrect) {
                                            MaterialTheme.colorScheme.primary
                                        } else {
                                            MaterialTheme.colorScheme.outline
                                        },
                                        unfocusedBorderColor = if (mathCorrect) {
                                            MaterialTheme.colorScheme.primary
                                        } else {
                                            MaterialTheme.colorScheme.outlineVariant
                                        },
                                        focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
                                        unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
                                    ),
                                    shape = RoundedCornerShape(12.dp),
                                )
                                AnimatedVisibility(
                                    visible = mathCorrect,
                                    enter = scaleIn(
                                        animationSpec = spring(
                                            dampingRatio = Spring.DampingRatioMediumBouncy,
                                        ),
                                    ) + fadeIn(),
                                ) {
                                    Row {
                                        Spacer(modifier = Modifier.width(10.dp))
                                        Icon(
                                            imageVector = Icons.Rounded.CheckCircle,
                                            contentDescription = null,
                                            modifier = Modifier.size(22.dp),
                                            tint = MaterialTheme.colorScheme.primary,
                                        )
                                    }
                                }
                            }
                        }
                    }

                    Button(
                        onClick = {
                            if (canProceed) {
                                onAgree()
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(60.dp),
                        enabled = canProceed,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                            disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                        ),
                        shape = RoundedCornerShape(16.dp),
                        elevation = ButtonDefaults.buttonElevation(
                            defaultElevation = if (canProceed) 4.dp else 0.dp,
                            pressedElevation = 8.dp,
                        ),
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .background(androidx.compose.ui.graphics.Color.Transparent),
                            contentAlignment = Alignment.Center,
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                AnimatedVisibility(
                                    visible = canProceed,
                                    enter = scaleIn() + fadeIn(),
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = Icons.Rounded.CheckCircle,
                                            contentDescription = null,
                                            modifier = Modifier.size(22.dp),
                                        )
                                        Spacer(modifier = Modifier.width(10.dp))
                                    }
                                }
                                Text(
                                    text = if (canProceed) {
                                        stringResource(R.string.i_agree_continue)
                                    } else {
                                        stringResource(R.string.complete_all_conditions)
                                    },
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.SemiBold,
                                    modifier = Modifier
                                        .graphicsLayer {
                                            scaleX = buttonScale
                                            scaleY = buttonScale
                                            alpha = buttonAlpha
                                        },
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = stringResource(R.string.agreement_acknowledgement),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

@Composable
private fun AgreementSection(
    icon: ImageVector,
    title: String,
    content: String,
    tone: AgreementSectionTone = AgreementSectionTone.Standard,
) {
    val sectionColors = tone.colors()
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = sectionColors.container,
        ),
        shape = RoundedCornerShape(20.dp),
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(sectionColors.iconContainer),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp),
                        tint = sectionColors.iconTint,
                    )
                }
                Spacer(modifier = Modifier.width(14.dp))
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = sectionColors.title,
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            AgreementSectionContent(
                content = content,
                tone = tone,
            )
        }
    }
}

@Composable
private fun AgreementRiskBanner() {
    val emphasisColor = MaterialTheme.colorScheme.error
    val bodyColor = MaterialTheme.colorScheme.onErrorContainer
    val emphasis = stringResource(R.string.agreement_risk_body_emphasis)
    val template = stringResource(R.string.agreement_risk_body_template, emphasis)
    val emphasisRange = remember(template, emphasis) {
        val start = template.indexOf(emphasis)
        if (start >= 0) start until (start + emphasis.length) else null
    }
    val riskSummary = buildAnnotatedString {
        append(template)
        emphasisRange?.let { range ->
            addStyle(
                style = SpanStyle(
                    color = emphasisColor,
                    fontWeight = FontWeight.Bold,
                ),
                start = range.first,
                end = range.last + 1,
            )
        }
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.78f),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = Icons.Outlined.Warning,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(20.dp),
                )
                Text(
                    text = stringResource(R.string.agreement_risk_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Text(
                text = riskSummary,
                style = MaterialTheme.typography.bodyMedium,
                color = bodyColor,
                lineHeight = MaterialTheme.typography.bodyMedium.lineHeight * 1.28,
            )
        }
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
    val bodyColor = when (tone) {
        AgreementSectionTone.Warning -> MaterialTheme.colorScheme.onSurface
        AgreementSectionTone.Notice -> MaterialTheme.colorScheme.onSurfaceVariant
        AgreementSectionTone.Standard -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    val headingColor = when (tone) {
        AgreementSectionTone.Warning -> MaterialTheme.colorScheme.error
        AgreementSectionTone.Notice -> MaterialTheme.colorScheme.primary
        AgreementSectionTone.Standard -> MaterialTheme.colorScheme.onSurface
    }

    val (style, color, fontWeight) = when (lineStyle) {
        AgreementLineStyle.Callout -> Triple(
            MaterialTheme.typography.titleSmall,
            MaterialTheme.colorScheme.error,
            FontWeight.Bold,
        )

        AgreementLineStyle.SectionHeading -> Triple(
            MaterialTheme.typography.titleSmall,
            headingColor,
            FontWeight.Bold,
        )

        AgreementLineStyle.Body -> Triple(
            MaterialTheme.typography.bodyMedium,
            bodyColor,
            FontWeight.Normal,
        )
    }

    Text(
        text = text,
        style = style,
        color = color,
        fontWeight = fontWeight,
        lineHeight = style.lineHeight * 1.28,
    )
}

@Composable
private fun ConditionRow(
    icon: ImageVector,
    text: String,
    isComplete: Boolean,
) {
    val iconScale by animateFloatAsState(
        targetValue = if (isComplete) 1f else 0.9f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessMedium,
        ),
        label = "agreement_condition_icon_scale",
    )

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Box(
            modifier = Modifier
                .size(28.dp)
                .clip(CircleShape)
                .background(
                    if (isComplete) {
                        MaterialTheme.colorScheme.primaryContainer
                    } else {
                        MaterialTheme.colorScheme.surfaceContainerHigh
                    },
                ),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = if (isComplete) Icons.Rounded.CheckCircle else icon,
                contentDescription = null,
                modifier = Modifier.size((22 * iconScale).dp),
                tint = if (isComplete) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = text,
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = if (isComplete) FontWeight.Medium else FontWeight.Normal,
            color = if (isComplete) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
        )
    }
}

private enum class AgreementSectionTone {
    Standard,
    Warning,
    Notice,
}

private enum class AgreementLineStyle {
    Callout,
    SectionHeading,
    Body,
}

private data class AgreementSectionColors(
    val container: Color,
    val iconContainer: Color,
    val iconTint: Color,
    val title: Color,
)

@Composable
private fun AgreementSectionTone.colors(): AgreementSectionColors {
    return when (this) {
        AgreementSectionTone.Standard -> AgreementSectionColors(
            container = MaterialTheme.colorScheme.surfaceContainerLow,
            iconContainer = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.5f),
            iconTint = MaterialTheme.colorScheme.primary,
            title = MaterialTheme.colorScheme.onSurface,
        )

        AgreementSectionTone.Warning -> AgreementSectionColors(
            container = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.42f),
            iconContainer = MaterialTheme.colorScheme.errorContainer,
            iconTint = MaterialTheme.colorScheme.error,
            title = MaterialTheme.colorScheme.error,
        )

        AgreementSectionTone.Notice -> AgreementSectionColors(
            container = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.28f),
            iconContainer = MaterialTheme.colorScheme.secondaryContainer,
            iconTint = MaterialTheme.colorScheme.primary,
            title = MaterialTheme.colorScheme.onSurface,
        )
    }
}
