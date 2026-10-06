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

import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.ui.R
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue

/**
 * Monotonic signal used by dashboard navigation to request that the currently composed detector
 * card opens after it has been scrolled into view. A value of zero means no request.
 */
public val LocalDetectorCardExpansionSignal: ProvidableCompositionLocal<Long> =
    compositionLocalOf { 0L }

/**
 * A detector's card. Collapsed, it shows only what a reader scanning the dashboard needs: the
 * detector, its status and the verdict. Expanding it adds the [subtitle] describing what was
 * checked, the [headerFacts], the [summary], the [content] and the [footerActions].
 */
@Composable
public fun DetectorCardFrame(
    title: String,
    subtitle: String,
    status: DetectorStatus,
    verdict: String,
    summary: String,
    leadingIcon: ImageVector,
    modifier: Modifier = Modifier,
    miuixLeadingIcon: ImageVector? = null,
    miuixLeadingPainter: Painter? = null,
    leadingBadgeIcon: ImageVector? = null,
    leadingBadgeStatus: DetectorStatus? = null,
    leadingBadgeContentDescription: String? = null,
    expanded: Boolean? = null,
    onExpandedChange: ((Boolean) -> Unit)? = null,
    headerFacts: @Composable ColumnScope.() -> Unit = {},
    collapsedOverview: @Composable ColumnScope.() -> Unit = {},
    footerActions: @Composable ColumnScope.() -> Unit = {},
    content: @Composable ColumnScope.() -> Unit,
) {
    val appearance = rememberStatusAppearance(status)
    val leadingBadgeAppearance = rememberStatusAppearance(leadingBadgeStatus ?: status)
    var internalExpanded by rememberSaveable(title) { mutableStateOf(false) }
    var lastHandledExpansionSignal by rememberSaveable(title) { mutableStateOf(0L) }
    val expansionSignal = LocalDetectorCardExpansionSignal.current
    val isExpanded = expanded ?: internalExpanded
    val toggleDescription = stringResource(
        if (isExpanded) R.string.card_collapse else R.string.card_expand,
    )
    val haptics = LocalHapticFeedback.current
    val headerInteraction = remember { MutableInteractionSource() }
    val useMiuixToggleHaptics = adaptiveValue(material = false, miuix = true)
    val toggleExpandedAction: () -> Unit = {
        val next = !isExpanded
        if (expanded == null) internalExpanded = next
        onExpandedChange?.invoke(next)
    }
    val toggleExpanded: () -> Unit = {
        if (useMiuixToggleHaptics) {
            haptics.performHapticFeedback(
                if (!isExpanded) HapticFeedbackType.ToggleOn else HapticFeedbackType.ToggleOff,
            )
        }
        toggleExpandedAction()
    }

    LaunchedEffect(expansionSignal) {
        if (expansionSignal <= lastHandledExpansionSignal) return@LaunchedEffect
        lastHandledExpansionSignal = expansionSignal
        if (!isExpanded) {
            if (expanded == null) {
                internalExpanded = true
            } else {
                onExpandedChange?.invoke(true)
            }
        }
    }

    val cardContent: @Composable ColumnScope.() -> Unit = {
        DetectorCardHeader(
            title = title,
            status = status,
            verdict = verdict,
            leadingIcon = leadingIcon,
            miuixLeadingIcon = miuixLeadingIcon,
            miuixLeadingPainter = miuixLeadingPainter,
            appearance = appearance,
            leadingBadgeIcon = leadingBadgeIcon,
            leadingBadgeAppearance = leadingBadgeAppearance,
            leadingBadgeContentDescription = leadingBadgeContentDescription,
            isExpanded = isExpanded,
            toggleDescription = toggleDescription,
            headerInteraction = headerInteraction,
            toggleExpanded = toggleExpanded,
            collapsedOverview = collapsedOverview,
        )
        DetectorCardBody(
            subtitle = subtitle,
            verdict = verdict,
            summary = summary,
            isExpanded = isExpanded,
            headerFacts = headerFacts,
            collapsedOverview = collapsedOverview,
            footerActions = footerActions,
            content = content,
        )
    }

    DuckPanel(
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(0.dp),
        verticalArrangement = Arrangement.spacedBy(0.dp),
        onClick = if (isExpanded) null else toggleExpanded,
        materialShape = MaterialTheme.shapes.large,
        content = cardContent,
    )
}
