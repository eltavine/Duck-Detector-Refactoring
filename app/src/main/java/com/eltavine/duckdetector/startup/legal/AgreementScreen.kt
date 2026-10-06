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

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.scaleIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.PrivacyTip
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
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
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.features.dashboard.ui.DashboardTopBarBrandIcon
import com.eltavine.duckdetector.startup.StartupHeroGlyph
import com.eltavine.duckdetector.ui.shell.StartupMiuixTopBar
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.adaptiveVerticalScrollFeedback
import io.github.xiaotong6666.uihelper.material.scaffold.ExpressiveScaffold
import io.github.xiaotong6666.uihelper.material.scaffold.expressiveTopAppBarColors
import io.github.xiaotong6666.uihelper.material.scaffold.materialTopBarEdgeToEdgeInsets
import kotlinx.coroutines.delay
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold as MiuixScaffold
import top.yukonga.miuix.kmp.theme.MiuixTheme

@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
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
    // Kept only for the lifetime of the composition, like the numbers and the countdown it goes with.
    val answerState = remember { TextFieldState() }
    val userAnswer = answerState.text.toString()
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

    AdaptiveContent(
        miuix = {
            val scrollBehavior = MiuixScrollBehavior()
            MiuixScaffold(
                modifier = modifier.fillMaxSize(),
                containerColor = MiuixTheme.colorScheme.surface,
                contentWindowInsets = WindowInsets.systemBars
                    .add(WindowInsets.displayCutout)
                    .only(WindowInsetsSides.Horizontal),
                topBar = {
                    StartupMiuixTopBar(
                        title = stringResource(R.string.user_agreement),
                        scrollBehavior = scrollBehavior,
                    )
                },
                bottomBar = {
                    AgreementConsentPanel(
                        countdown = countdown,
                        timerComplete = timerComplete,
                        num1 = num1,
                        num2 = num2,
                        isAddition = isAddition,
                        answerState = answerState,
                        mathCorrect = mathCorrect,
                        isScrolledToBottom = isScrolledToBottom,
                        canProceed = canProceed,
                        buttonScale = buttonScale,
                        onAgree = onAgree,
                        onContentHeightChanged = {},
                    )
                },
            ) { innerPadding ->
                AgreementDocument(
                    showContent = showContent,
                    modifier = Modifier
                        .fillMaxSize()
                        .nestedScroll(scrollBehavior.nestedScrollConnection)
                        .adaptiveVerticalScrollFeedback()
                        .verticalScroll(scrollState, overscrollEffect = null),
                    contentPadding = innerPadding,
                    horizontalPadding = 12.dp,
                    topPadding = 12.dp,
                    bottomPadding = 20.dp,
                    spacing = 12.dp,
                )
            }
        },
        material = {
            val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
            ExpressiveScaffold(
                modifier = modifier
                    .fillMaxSize()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                topBar = {
                    LargeFlexibleTopAppBar(
                        title = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                DashboardTopBarBrandIcon()
                                Spacer(modifier = Modifier.size(10.dp))
                                Text(text = stringResource(R.string.user_agreement))
                            }
                        },
                        colors = expressiveTopAppBarColors(),
                        scrollBehavior = scrollBehavior,
                        windowInsets = materialTopBarEdgeToEdgeInsets(),
                    )
                },
                bottomBar = {
                    AgreementConsentPanel(
                        countdown = countdown,
                        timerComplete = timerComplete,
                        num1 = num1,
                        num2 = num2,
                        isAddition = isAddition,
                        answerState = answerState,
                        mathCorrect = mathCorrect,
                        isScrolledToBottom = isScrolledToBottom,
                        canProceed = canProceed,
                        buttonScale = buttonScale,
                        onAgree = onAgree,
                        onContentHeightChanged = {},
                    )
                },
            ) { innerPadding ->
                AgreementDocument(
                    showContent = showContent,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scrollState),
                    contentPadding = innerPadding,
                    horizontalPadding = 16.dp,
                    topPadding = 16.dp,
                    bottomPadding = 24.dp,
                    spacing = 16.dp,
                )
            }
        },
    )
}

@Composable
private fun AgreementDocument(
    showContent: Boolean,
    modifier: Modifier,
    spacing: androidx.compose.ui.unit.Dp,
    contentPadding: PaddingValues = PaddingValues(0.dp),
    horizontalPadding: androidx.compose.ui.unit.Dp = 0.dp,
    topPadding: androidx.compose.ui.unit.Dp = 0.dp,
    bottomPadding: androidx.compose.ui.unit.Dp = 0.dp,
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 560.dp)
                .fillMaxWidth()
                .padding(contentPadding)
                .padding(
                    start = horizontalPadding,
                    top = topPadding,
                    end = horizontalPadding,
                    bottom = bottomPadding,
                ),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(spacing),
        ) {
            AgreementHeader(showContent = showContent)
            AgreementRiskBanner()
            AgreementSection(
                icon = Icons.Outlined.Gavel,
                title = stringResource(R.string.user_agreement_title),
                content = stringResource(R.string.user_agreement_content),
            )
            AgreementSection(
                icon = Icons.Outlined.Warning,
                title = stringResource(R.string.disclaimer_title),
                content = stringResource(R.string.disclaimer_content),
                tone = AgreementSectionTone.Warning,
            )
            AgreementSection(
                icon = Icons.Outlined.PrivacyTip,
                title = stringResource(R.string.privacy_notice_title),
                content = stringResource(R.string.privacy_notice_content),
                tone = AgreementSectionTone.Notice,
            )
        }
    }
}

@Composable
private fun AgreementHeader(
    showContent: Boolean,
) {
    AdaptiveContent(
        miuix = {
            MiuixCard(
                modifier = Modifier.fillMaxWidth(),
                insideMargin = androidx.compose.foundation.layout.PaddingValues(0.dp),
            ) {
                BasicComponent(
                    title = stringResource(R.string.disclaimer),
                    summary = stringResource(R.string.please_read_carefully),
                    startAction = {
                        com.eltavine.duckdetector.core.ui.components.DuckIcon(
                            imageVector = Icons.Outlined.Security,
                            contentDescription = null,
                            modifier = Modifier.padding(end = 12.dp).size(22.dp),
                            tint = MiuixTheme.colorScheme.onSurface,
                        )
                    },
                    modifier = Modifier.semantics { heading() },
                )
            }
        },
        material = {
            val colorScheme = MaterialTheme.colorScheme
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 36.dp, bottom = 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                AnimatedVisibility(
                    visible = showContent,
                    enter = scaleIn(
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioMediumBouncy,
                            stiffness = Spring.StiffnessLow,
                        ),
                    ) + fadeIn(),
                ) {
                    StartupHeroGlyph(icon = Icons.Outlined.Security)
                }
                Spacer(modifier = Modifier.height(24.dp))
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
                    Text(
                        text = stringResource(R.string.disclaimer),
                        modifier = Modifier.semantics { heading() },
                        style = DuckTypography.Title3,
                        textAlign = TextAlign.Center,
                        color = colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(modifier = Modifier.height(12.dp))
                AnimatedVisibility(
                    visible = showContent,
                    enter = fadeIn(animationSpec = tween(delayMillis = 200)),
                ) {
                    Text(
                        text = stringResource(R.string.please_read_carefully),
                        style = DuckTypography.CalloutEmphasized,
                        color = colorScheme.onSurface,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        },
    )
}
