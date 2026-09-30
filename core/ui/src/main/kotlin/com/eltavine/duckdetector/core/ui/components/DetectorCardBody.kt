/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.core.VisibilityThreshold
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.adaptiveInsetSurfaceColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSecondaryTextColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceBackground
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSurfaceClip
import top.yukonga.miuix.kmp.anim.folmeSpring
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun DetectorCardBody(
    subtitle: String,
    verdict: String,
    summary: String,
    isExpanded: Boolean,
    headerFacts: @Composable ColumnScope.() -> Unit,
    collapsedOverview: @Composable ColumnScope.() -> Unit,
    footerActions: @Composable ColumnScope.() -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    AdaptiveContent(
        miuix = {
            AnimatedVisibility(
                visible = isExpanded,
                enter = expandVertically(
                    animationSpec = folmeSpring(
                        damping = 1.0f,
                        response = 0.36f,
                        visibilityThreshold = IntSize.VisibilityThreshold,
                    ),
                    expandFrom = Alignment.Top,
                ) + fadeIn(animationSpec = folmeSpring(damping = 1.0f, response = 0.30f)),
                exit = shrinkVertically(
                    animationSpec = folmeSpring(
                        damping = 1.0f,
                        response = 0.30f,
                        visibilityThreshold = IntSize.VisibilityThreshold,
                    ),
                    shrinkTowards = Alignment.Top,
                ) + fadeOut(animationSpec = folmeSpring(damping = 1.0f, response = 0.23f)),
            ) {
                // Section rows stay folded by default, so the outer height transition measures
                // short summaries, not all of TEE's attestation values at once.
                Column(
                    modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        if (verdict.isNotBlank()) {
                            WrapSafeText(
                                text = verdict,
                                modifier = Modifier.fillMaxWidth(),
                                style = DuckTypography.PanelBody.copy(fontWeight = FontWeight.Medium),
                                color = MiuixTheme.colorScheme.onSurface,
                            )
                        }
                        if (subtitle.isNotBlank()) {
                            WrapSafeText(
                                text = subtitle,
                                modifier = Modifier.fillMaxWidth(),
                                style = DuckTypography.PanelSupporting,
                                color = adaptiveSecondaryTextColor(),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                        headerFacts()
                        if (summary.isNotBlank()) {
                            WrapSafeText(
                                text = summary,
                                modifier = Modifier.fillMaxWidth(),
                                style = DuckTypography.PanelSupporting,
                                color = adaptiveSecondaryTextColor(),
                            )
                        }
                    }
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp)
                            .adaptiveSurfaceBackground(
                                materialColor = Color.Transparent,
                                materialShape = MaterialTheme.shapes.large,
                                miuixColor = adaptiveInsetSurfaceColor(),
                                miuixCornerRadius = 16.dp,
                            )
                            .adaptiveSurfaceClip(
                                materialShape = MaterialTheme.shapes.large,
                                miuixCornerRadius = 16.dp,
                            ),
                        verticalArrangement = Arrangement.spacedBy(0.dp),
                        content = content,
                    )
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                        content = footerActions,
                    )
                }
            }
        },
        material = {
            // One state/size transition for the mutually exclusive Material overview and details.
            // Two independent AnimatedVisibility size animations cause the overview to release its
            // height while the details are still growing, producing a visible two-stage jump.
            AnimatedContent(
                targetState = isExpanded,
                transitionSpec = {
                    (fadeIn(MotionTokens.FadeInOut) togetherWith fadeOut(MotionTokens.FadeInOut))
                        .using(
                            SizeTransform(clip = true) { _, _ ->
                                MotionTokens.smoothSpring(IntSize.VisibilityThreshold)
                            },
                        )
                },
                label = "materialDetectorBody",
            ) {
                if (it) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            if (verdict.isNotBlank()) {
                                WrapSafeText(
                                    text = verdict,
                                    modifier = Modifier.fillMaxWidth(),
                                    style = DuckTypography.PanelBody.copy(fontWeight = FontWeight.Medium),
                                    color = MaterialTheme.colorScheme.onSurface,
                                )
                            }
                            if (subtitle.isNotBlank()) {
                                WrapSafeText(
                                    text = subtitle,
                                    modifier = Modifier.fillMaxWidth(),
                                    style = DuckTypography.PanelSupporting,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            headerFacts()
                            if (summary.isNotBlank()) {
                                WrapSafeText(
                                    text = summary,
                                    modifier = Modifier.fillMaxWidth(),
                                    style = DuckTypography.PanelSupporting,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                            content = content,
                        )
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                            content = footerActions,
                        )
                    }
                } else {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        content = collapsedOverview,
                    )
                }
            }
        },
    )
}
