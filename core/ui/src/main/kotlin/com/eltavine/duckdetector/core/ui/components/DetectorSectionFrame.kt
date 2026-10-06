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

import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.ui.R
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveExpandableSection
import io.github.xiaotong6666.uihelper.adaptive.LocalAdaptiveSectionGeometry
import io.github.xiaotong6666.uihelper.adaptive.adaptiveErrorColor
import io.github.xiaotong6666.uihelper.adaptive.rememberExpandableSectionState
import io.github.xiaotong6666.uihelper.common.StatusTag

/**
 * One expandable evidence group across both skins. Duck owns severity semantics; uihelper owns
 * native container, interaction, chevron and expansion motion.
 */
@Composable
public fun DetectorSectionFrame(
    title: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    severity: SectionSeverity? = null,
    stateKey: String? = null,
    showDivider: Boolean = true,
    showMiuixIcon: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    val sectionState = rememberExpandableSectionState(identity = stateKey)
    val materialShape = LocalAdaptiveSectionGeometry.current

    AdaptiveExpandableSection(
        title = title,
        icon = icon,
        expanded = sectionState.expanded,
        onToggle = sectionState::toggle,
        modifier = modifier,
        showDivider = adaptiveValue(material = false, miuix = showDivider),
        materialDividerColor = DuckTheme.palette.separator,
        materialContainerColor = DuckTheme.palette.groupedInset,
        materialIconRotationSpec = MotionTokens.IconRotation,
        materialExpandSpec = MotionTokens.smoothSpring(IntSize.VisibilityThreshold),
        materialFadeSpec = MotionTokens.FadeInOut,
        materialTopRadius = materialShape.topRadius,
        materialBottomRadius = materialShape.bottomRadius,
        miuixIcon = if (showMiuixIcon) icon else null,
        trailingContent = {
            severity?.let { resolvedSeverity ->
                val label = sectionSeverityLabel(resolvedSeverity)
                AdaptiveContent(
                    miuix = {
                        val accent = when (resolvedSeverity) {
                            SectionSeverity.HIGH -> adaptiveErrorColor()
                            SectionSeverity.MEDIUM -> DuckTheme.palette.caution
                            SectionSeverity.PROBE_ERROR -> DuckTheme.palette.critical
                        }
                        StatusTag(
                            label = label,
                            backgroundColor = accent.copy(alpha = 0.16f),
                            contentColor = accent,
                        )
                    },
                    material = {
                        MaterialSeverityTag(
                            status = resolvedSeverity.representativeStatus(),
                            label = label,
                        )
                    },
                )
            }
        },
        content = {
            CompositionLocalProvider(LocalMaterialDetectorHairlineStartInset provides 28.dp) {
                content()
            }
        },
    )
}

@Composable
private fun sectionSeverityLabel(severity: SectionSeverity): String = stringResource(
    when (severity) {
        SectionSeverity.HIGH -> R.string.severity_high
        SectionSeverity.MEDIUM -> R.string.severity_medium
        SectionSeverity.PROBE_ERROR -> R.string.status_info_error
    },
)
