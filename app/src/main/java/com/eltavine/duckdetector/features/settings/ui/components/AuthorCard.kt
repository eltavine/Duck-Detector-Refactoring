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

import android.graphics.BitmapFactory
import android.os.SystemClock
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.BugReport
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
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.input.pointer.positionChangeIgnoreConsumed
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalDensity
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.ui.theme.ShapeTokens
import compose.icons.SimpleIcons
import compose.icons.simpleicons.Assemblyscript
import compose.icons.simpleicons.Cplusplus
import compose.icons.simpleicons.Figma
import compose.icons.simpleicons.Kotlin
import org.json.JSONArray
import kotlin.math.abs

@Composable
fun AuthorCard(
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val contributorSnapshots = remember(context) { loadContributorSnapshots(context) }
    val authors = contributorSnapshots.map { snapshot ->
        AuthorProfile(
            login = snapshot.login,
            name = snapshot.name,
            profileUrl = snapshot.profileUrl,
            avatarAssetPath = snapshot.avatarAssetPath,
            contributionSummary = stringResource(summaryResIdForKey(snapshot.summaryKey)),
            contributions = snapshot.contributionKeys.mapNotNull(::authorContributionForKey),
        )
    }
    if (authors.isEmpty()) {
        return
    }
    val pagerState = rememberPagerState(pageCount = { authors.size })
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
    val context = LocalContext.current
    Surface(
        modifier = modifier
            .height(404.dp)
            .clip(ShapeTokens.CornerExtraLargeIncreased)
            .clickable {
                openExternalUri(context, profile.profileUrl)
            },
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        tonalElevation = 0.dp,
        shadowElevation = 0.dp,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxSize()
                .padding(horizontal = 22.dp, vertical = 22.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(64.dp),
                contentAlignment = Alignment.Center,
            ) {
                WrapSafeText(
                    text = profile.name,
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontWeight = FontWeight.Bold,
                    ),
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.fillMaxWidth(),
                )
            }

            AuthorAvatar(
                profile = profile,
                modifier = Modifier
                    .size(132.dp),
            )

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(72.dp),
                contentAlignment = Alignment.Center,
            ) {
                WrapSafeText(
                    text = profile.contributionSummary,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Row(
                modifier = Modifier.height(40.dp),
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
private fun AuthorAvatar(
    profile: AuthorProfile,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val avatarBitmap = remember(profile.avatarAssetPath, context) {
        profile.avatarAssetPath?.let { assetPath ->
            runCatching {
                context.assets.open(assetPath).use { stream ->
                    BitmapFactory.decodeStream(stream)?.asImageBitmap()
                }
            }.getOrNull()
        }
    }

    Box(
        modifier = modifier
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.surface)
            .border(
                BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                CircleShape,
            ),
        contentAlignment = Alignment.Center,
    ) {
        when {
            avatarBitmap != null -> {
                Image(
                    bitmap = avatarBitmap,
                    contentDescription = profile.name,
                    contentScale = ContentScale.Crop,
                    modifier = Modifier.fillMaxSize(),
                )
            }

            else -> {
                WrapSafeText(
                    text = profile.name.firstOrNull()?.uppercase() ?: "?",
                    style = MaterialTheme.typography.headlineMedium.copy(fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
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
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarAssetPath: String?,
    val contributionSummary: String,
    val contributions: List<AuthorContribution>,
)

private data class ContributorSnapshot(
    val login: String,
    val name: String,
    val profileUrl: String,
    val avatarAssetPath: String?,
    val summaryKey: String?,
    val contributionKeys: List<String>,
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

    data object Security : AuthorContribution(
        label = "Security",
        icon = Icons.Rounded.BugReport,
        tint = Color(0xFFD32F2F),
    )
}

private fun loadContributorSnapshots(context: android.content.Context): List<ContributorSnapshot> {
    val assetManager = context.assets
    val payload = runCatching {
        assetManager.open(CONTRIBUTORS_ASSET_FILE_NAME).bufferedReader(Charsets.UTF_8).use { reader ->
            reader.readText()
        }
    }.getOrNull() ?: return emptyList()
    return runCatching {
        val array = JSONArray(payload)
        buildList(array.length()) {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val login = item.optString("login").trim()
                val name = item.optString("name").trim().ifBlank { login }
                if (login.isBlank()) {
                    continue
                }
                add(
                    ContributorSnapshot(
                        login = login,
                        name = name,
                        profileUrl = item.optString("profileUrl").trim().ifBlank { "https://github.com/$login" },
                        avatarAssetPath = item.optString("avatarAssetPath").trim().ifBlank { null },
                        summaryKey = item.optString("summaryKey").trim().ifBlank { null },
                        contributionKeys = item.optJSONArray("contributionKeys").toStringList(),
                    )
                )
            }
        }
    }.getOrDefault(emptyList())
}

private fun summaryResIdForKey(summaryKey: String?): Int {
    return when (summaryKey) {
        "author_summary_eltavine" -> R.string.author_summary_eltavine
        "author_summary_baka" -> R.string.author_summary_baka
        "author_summary_xiaotong" -> R.string.author_summary_xiaotong
        "author_summary_searchur" -> R.string.author_summary_searchur
        "author_summary_wxx" -> R.string.author_summary_wxx
        "author_summary_alex" -> R.string.author_summary_alex
        "author_summary_hsskyboy" -> R.string.author_summary_hsskyboy
        "author_summary_lingqing" -> R.string.author_summary_lingqing
        "author_summary_qwq233" -> R.string.author_summary_qwq233
        "author_summary_sqmy" -> R.string.author_summary_sqmy
        "author_summary_victor" -> R.string.author_summary_victor
        "author_summary_zg089" -> R.string.author_summary_zg089
        "author_summary_coolzyd" -> R.string.author_summary_coolzyd
        "author_summary_947409161" -> R.string.author_summary_947409161
        "author_summary_mirin" -> R.string.author_summary_mirin
        "author_summary_aviraxp" -> R.string.author_summary_aviraxp
        "author_summary_5ec1cff" -> R.string.author_summary_5ec1cff
        else -> R.string.author_summary_default
    }
}

private fun authorContributionForKey(key: String): AuthorContribution? {
    return when (key.lowercase()) {
        "ui" -> AuthorContribution.Ui
        "cpp" -> AuthorContribution.Cpp
        "asm" -> AuthorContribution.Asm
        "kotlin" -> AuthorContribution.Kotlin
        "security" -> AuthorContribution.Security
        else -> null
    }
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) {
        return emptyList()
    }
    return buildList(length()) {
        for (index in 0 until length()) {
            val value = optString(index).trim()
            if (value.isNotEmpty()) {
                add(value)
            }
        }
    }
}

private const val CONTRIBUTORS_ASSET_FILE_NAME = "github_contributors.json"
