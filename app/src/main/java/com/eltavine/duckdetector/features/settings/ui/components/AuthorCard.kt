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

package com.eltavine.duckdetector.features.settings.ui.components

import android.os.SystemClock
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Swipe
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChangeIgnoreConsumed
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalDensity
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.ui.theme.ShapeTokens
import compose.icons.SimpleIcons
import compose.icons.simpleicons.Assemblyscript
import compose.icons.simpleicons.Cplusplus
import compose.icons.simpleicons.Figma
import compose.icons.simpleicons.Kotlin
import kotlin.math.abs

@Composable
fun AuthorCard(
    modifier: Modifier = Modifier,
) {
    val authors = listOf(
        AuthorProfile(
            name = "Eltavine",
            portraitRes = R.drawable.eltavine,
            contributionSummary = stringResource(R.string.author_summary_eltavine),
            contributions = listOf(
                AuthorContribution.Ui,
                AuthorContribution.Cpp,
                AuthorContribution.Asm,
                AuthorContribution.Kotlin,
            ),
        ),
        AuthorProfile(
            name = "芙兰朵布丁",
            portraitRes = R.drawable.baka,
            contributionSummary = stringResource(R.string.author_summary_baka),
            contributions = listOf(
                AuthorContribution.Cpp,
                AuthorContribution.Kotlin,
            ),
        ),
        AuthorProfile(
            name = "XiaoTong6666",
            portraitRes = R.drawable.xiaotong,
            contributionSummary = stringResource(R.string.author_summary_xiaotong),
            contributions = listOf(
                AuthorContribution.Cpp,
                AuthorContribution.Kotlin,
            ),
        ),
        AuthorProfile(
            name = "wxxsfxyzm",
            portraitRes = R.drawable.wxxsfxyzm,
            contributionSummary = stringResource(R.string.author_summary_wxx),
            contributions = listOf(
                AuthorContribution.Kotlin,
            ),
        ),
    )
    val pagerState = rememberPagerState(pageCount = { authors.size })
    val context = LocalContext.current
    val haptics = LocalHapticFeedback.current
    val density = LocalDensity.current
    val dragThresholdPx = with(density) { 42.dp.toPx() }
    var lastBoundaryFeedbackAt by remember { mutableLongStateOf(0L) }
    val boundaryToastText = stringResource(R.string.author_boundary_toast)

    val triggerBoundaryFeedback = {
        val now = SystemClock.elapsedRealtime()
        if (now - lastBoundaryFeedbackAt < 850L) {
            Unit
        } else {
            lastBoundaryFeedbackAt = now
            haptics.performHapticFeedback(HapticFeedbackType.LongPress)
            Toast.makeText(context, boundaryToastText, Toast.LENGTH_SHORT).show()
        }
    }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        HorizontalPager(
            state = pagerState,
            contentPadding = PaddingValues(horizontal = 28.dp),
            pageSpacing = 16.dp,
            modifier = Modifier
                .fillMaxWidth()
                .pointerInput(authors.size) {
                    awaitEachGesture {
                        val startPage = pagerState.currentPage
                        val down = awaitFirstDown(pass = PointerEventPass.Initial)
                        var totalHorizontalDrag = 0f

                        while (true) {
                            val event = awaitPointerEvent(pass = PointerEventPass.Final)
                            val change = event.changes.firstOrNull { it.id == down.id } ?: break
                            totalHorizontalDrag += change.positionChangeIgnoreConsumed().x
                            if (!change.pressed) {
                                break
                            }
                        }

                        if (abs(totalHorizontalDrag) < dragThresholdPx) {
                            return@awaitEachGesture
                        }

                        val triedBeforeFirst = startPage == 0 && totalHorizontalDrag > 0f
                        val triedAfterLast =
                            startPage == authors.lastIndex && totalHorizontalDrag < 0f
                        if (triedBeforeFirst || triedAfterLast) {
                            triggerBoundaryFeedback()
                        }
                    }
                },
        ) { page ->
            Box(
                modifier = Modifier.fillMaxWidth(),
                contentAlignment = Alignment.Center,
            ) {
                AuthorPage(
                    profile = authors[page],
                    modifier = Modifier.fillMaxWidth(0.92f),
                )
            }
        }

        SwipeHintNote(
            pageCount = authors.size,
            currentPage = pagerState.currentPage + 1,
        )
    }
}

@Composable
private fun AuthorPage(
    profile: AuthorProfile,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        tonalElevation = 0.dp,
        shadowElevation = 0.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 22.dp, vertical = 22.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            WrapSafeText(
                text = profile.name,
                style = MaterialTheme.typography.headlineMedium.copy(
                    fontWeight = FontWeight.Bold,
                ),
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.fillMaxWidth(),
            )

            Image(
                painter = painterResource(id = profile.portraitRes),
                contentDescription = profile.name,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .size(132.dp)
                    .clip(CircleShape)
                    .border(
                        width = 1.dp,
                        color = MaterialTheme.colorScheme.outlineVariant,
                        shape = CircleShape,
                    ),
            )

            WrapSafeText(
                text = profile.contributionSummary,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                profile.contributions.forEach { contribution ->
                    ContributionIcon(contribution = contribution)
                }
            }
        }
    }
}

@Composable
private fun SwipeHintNote(
    pageCount: Int,
    currentPage: Int,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = ShapeTokens.CornerLarge,
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        tonalElevation = 0.dp,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(28.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.secondaryContainer),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Swipe,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(16.dp),
                )
            }

            WrapSafeText(
                text = if (pageCount > 1) {
                    stringResource(R.string.author_swipe_hint_paged, currentPage, pageCount)
                } else {
                    stringResource(R.string.author_swipe_hint_single)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ContributionIcon(
    contribution: AuthorContribution,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        shape = ShapeTokens.CornerFull,
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 0.dp,
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .padding(9.dp),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = contribution.icon,
                contentDescription = contribution.label,
                tint = contribution.tint,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}

private data class AuthorProfile(
    val name: String,
    val portraitRes: Int,
    val contributionSummary: String,
    val contributions: List<AuthorContribution>,
)

private sealed class AuthorContribution(
    val label: String,
    val icon: ImageVector,
    val tint: Color,
) {
    data object Ui : AuthorContribution(
        label = "UI",
        icon = SimpleIcons.Figma,
        tint = Color(0xFFF24E1E),
    )

    data object Cpp : AuthorContribution(
        label = "C++",
        icon = SimpleIcons.Cplusplus,
        tint = Color(0xFF00599C),
    )

    data object Asm : AuthorContribution(
        label = "ASM",
        icon = SimpleIcons.Assemblyscript,
        tint = Color(0xFF007AAC),
    )

    data object Kotlin : AuthorContribution(
        label = "Kotlin",
        icon = SimpleIcons.Kotlin,
        tint = Color(0xFF7F52FF),
    )
}
