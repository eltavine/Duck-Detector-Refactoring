/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.indication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.ui.presentation.StatusAppearance
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveExpandIcon
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveIcon
import io.github.xiaotong6666.uihelper.adaptive.adaptiveInsetSurfaceColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceBackground
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue
import top.yukonga.miuix.kmp.basic.BasicComponent
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun DetectorCardHeader(
    title: String,
    status: DetectorStatus,
    verdict: String,
    leadingIcon: ImageVector,
    miuixLeadingIcon: ImageVector?,
    miuixLeadingPainter: Painter?,
    appearance: StatusAppearance,
    leadingBadgeIcon: ImageVector?,
    leadingBadgeAppearance: StatusAppearance,
    leadingBadgeContentDescription: String?,
    isExpanded: Boolean,
    toggleDescription: String,
    headerInteraction: MutableInteractionSource,
    toggleExpanded: () -> Unit,
    collapsedOverview: @Composable ColumnScope.() -> Unit,
) {
    AdaptiveContent(
        miuix = {
            val verdictColor by animateColorAsState(
                targetValue = if (isExpanded) {
                    MiuixTheme.colorScheme.onSurface
                } else {
                    MiuixTheme.colorScheme.onSurfaceVariantSummary
                },
                animationSpec = tween(durationMillis = 260),
                label = "miuixDetectorVerdictColor",
            )
            BasicComponent(
                startAction = {
                    MiuixCardGlyph(
                        icon = miuixLeadingIcon ?: leadingIcon,
                        painter = miuixLeadingPainter,
                        badgeIcon = leadingBadgeIcon,
                        badgeAppearance = leadingBadgeAppearance,
                        badgeContentDescription = leadingBadgeContentDescription,
                    )
                },
                endActions = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CompactStatusBadge(status = status)
                        AdaptiveExpandIcon(expanded = isExpanded, miuixSize = 16.dp)
                    }
                },
                // The outer card handles taps while collapsed; only the header collapses it.
                onClick = if (isExpanded) toggleExpanded else null,
                onClickLabel = toggleDescription,
                role = Role.Button,
                interactionSource = headerInteraction,
            ) {
                WrapSafeText(
                    text = title,
                    style = MiuixTheme.textStyles.headline1.copy(fontWeight = FontWeight.Medium),
                    color = MiuixTheme.colorScheme.onSurface,
                )
                if (verdict.isNotBlank()) {
                    AnimatedVisibility(
                        visible = !isExpanded,
                        enter = expandVertically(
                            animationSpec = tween(durationMillis = 280, delayMillis = 90),
                            expandFrom = Alignment.Top,
                        ) + fadeIn(
                            animationSpec = tween(durationMillis = 150, delayMillis = 90),
                        ),
                        exit = shrinkVertically(
                            animationSpec = tween(durationMillis = 280),
                            shrinkTowards = Alignment.Top,
                        ) + fadeOut(animationSpec = tween(durationMillis = 150)),
                    ) {
                        WrapSafeText(
                            text = verdict,
                            style = MiuixTheme.textStyles.body2,
                            color = verdictColor,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
            }
            if (!isExpanded) {
                Column(
                    modifier = Modifier.padding(horizontal = 16.dp),
                    content = collapsedOverview,
                )
            }
        },
        material = {
            // Collapsed: the native Card owns the entire hit area and indication, including its
            // padding and collapsed overview. Expanded: only the flush-to-edge header can collapse.
            // Do not clip the inset glyph row: its small badge deliberately extends past the tile.
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .indication(headerInteraction, LocalIndication.current)
                    .then(
                        if (!isExpanded) Modifier else Modifier
                            .clickable(
                                interactionSource = headerInteraction,
                                indication = null,
                                role = Role.Button,
                                onClickLabel = toggleDescription,
                                onClick = toggleExpanded,
                            ),
                    )
                    .padding(
                        start = 16.dp,
                        end = 16.dp,
                        top = 16.dp,
                        bottom = adaptiveValue(
                            material = if (isExpanded) 12.dp else 28.dp,
                            miuix = 18.dp,
                        ),
                    ),
                verticalArrangement = Arrangement.spacedBy(0.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    CardGlyph(
                        icon = leadingIcon,
                        appearance = appearance,
                        badgeIcon = leadingBadgeIcon,
                        badgeAppearance = leadingBadgeAppearance,
                        badgeContentDescription = leadingBadgeContentDescription,
                    )
                    Column(
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(2.dp),
                    ) {
                        WrapSafeText(
                            text = title,
                            style = DuckTypography.PanelTitle,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        if (verdict.isNotBlank()) {
                            AnimatedVisibility(
                                visible = !isExpanded,
                                enter = expandVertically(
                                    animationSpec = MotionTokens.smoothSpring(IntSize.VisibilityThreshold),
                                    expandFrom = Alignment.Top,
                                ) + fadeIn(
                                    animationSpec = tween(durationMillis = 150, delayMillis = 120),
                                ),
                                exit = shrinkVertically(
                                    animationSpec = MotionTokens.smoothSpring(IntSize.VisibilityThreshold),
                                    shrinkTowards = Alignment.Top,
                                ) + fadeOut(animationSpec = tween(durationMillis = 120)),
                            ) {
                                WrapSafeText(
                                    text = verdict,
                                    style = DuckTypography.PanelSupporting,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 2,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                        }
                    }
                    CompactStatusBadge(status = status)
                    AdaptiveExpandIcon(expanded = isExpanded)
                }
            }
        },
    )
}

@Composable
private fun MiuixCardGlyph(
    icon: ImageVector,
    painter: Painter?,
    badgeIcon: ImageVector?,
    badgeAppearance: StatusAppearance,
    badgeContentDescription: String?,
) {
    Box(modifier = Modifier.size(24.dp), contentAlignment = Alignment.Center) {
        if (painter != null) {
            AdaptiveIcon(
                painter = painter,
                contentDescription = null,
                modifier = Modifier.size(24.dp),
                tint = MiuixTheme.colorScheme.onSurface,
            )
        } else {
            AdaptiveIcon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(24.dp),
                tint = MiuixTheme.colorScheme.onSurface,
            )
        }
        if (badgeIcon != null) {
            Box(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 3.dp, y = 3.dp)
                    .size(14.dp)
                    .background(MiuixTheme.colorScheme.surfaceContainer, CircleShape)
                    .padding(1.dp),
                contentAlignment = Alignment.Center,
            ) {
                AdaptiveIcon(
                    imageVector = badgeIcon,
                    contentDescription = badgeContentDescription,
                    modifier = Modifier.size(12.dp),
                    tint = badgeAppearance.iconTint,
                )
            }
        }
    }
}

@Composable
private fun CardGlyph(
    icon: ImageVector,
    appearance: StatusAppearance,
    badgeIcon: ImageVector?,
    badgeAppearance: StatusAppearance,
    badgeContentDescription: String?,
) {
    Box(
        modifier = Modifier
            .size(44.dp)
            .adaptiveSurfaceBackground(
                materialColor = MaterialTheme.colorScheme.secondaryContainer,
                materialShape = MaterialTheme.shapes.medium,
                miuixColor = adaptiveInsetSurfaceColor(),
                miuixCornerRadius = 14.dp,
            ),
        contentAlignment = Alignment.Center,
    ) {
        AdaptiveIcon(imageVector = icon, contentDescription = null, tint = appearance.iconTint)
        if (badgeIcon != null) {
            Box(
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 5.dp, y = 5.dp)
                    .size(20.dp)
                    .background(color = DuckTheme.palette.groupedSurface, shape = CircleShape)
                    .padding(2.dp),
                contentAlignment = Alignment.Center,
            ) {
                AdaptiveIcon(
                    imageVector = badgeIcon,
                    contentDescription = badgeContentDescription,
                    tint = badgeAppearance.iconTint,
                )
            }
        }
    }
}
