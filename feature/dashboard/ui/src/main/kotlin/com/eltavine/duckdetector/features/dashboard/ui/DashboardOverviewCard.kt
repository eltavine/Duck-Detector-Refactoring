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

package com.eltavine.duckdetector.features.dashboard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Timer
import androidx.compose.material.icons.rounded.ArrowForward
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.materialStatusTone
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.StatusAppearance
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewMetricModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import io.github.xiaotong6666.uihelper.miuix.primitive.StatusHeroCardMiuix
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.basic.VerticalDivider as MiuixVerticalDivider

@Composable
internal fun DashboardOverviewCard(
    model: DashboardOverviewModel,
    onExportReport: () -> Unit,
) {
    val appearance = rememberStatusAppearance(model.status)
    val buildInfo = LocalAppBuildInfo.current
    val versionLabel = "${buildInfo.versionName} (${buildInfo.versionCode})"
    val buildTimeLabel = stringResource(R.string.dashboard_build_time_utc, formatBuildTimeUtc(buildInfo.buildTimeUtc))
    if (LocalUiMode.current == UiMode.Miuix) {
        // Reuse the status-first MIUIX hero (also used by FuseHide's UI vocabulary),
        // with a large decorative severity signal in the lower-right corner.
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val tone = model.status.severity
            StatusHeroCardMiuix(
                title = model.headline,
                summary = model.summary,
                icon = when (tone) {
                    DetectionSeverity.DANGER -> Icons.Rounded.ErrorOutline
                    DetectionSeverity.WARNING -> Icons.Rounded.WarningAmber
                    DetectionSeverity.ALL_CLEAR -> Icons.Rounded.CheckCircleOutline
                    DetectionSeverity.INFO -> Icons.Rounded.Info
                },
                containerColor = when (tone) {
                    DetectionSeverity.DANGER -> MiuixTheme.colorScheme.errorContainer
                    DetectionSeverity.WARNING, DetectionSeverity.ALL_CLEAR ->
                        lerp(MiuixTheme.colorScheme.surfaceContainer, appearance.iconTint, 0.15f)
                    DetectionSeverity.INFO -> MiuixTheme.colorScheme.surfaceContainerHighest
                },
                accentColor = if (tone == DetectionSeverity.DANGER) MiuixTheme.colorScheme.error else appearance.iconTint,
                onClick = onExportReport,
                metaContent = {
                    ReportHeroMetadata(
                        versionLabel = versionLabel,
                        buildTimeLabel = buildTimeLabel,
                        contentColor = MiuixTheme.colorScheme.onSurface,
                    )
                },
                actionContent = {
                    ReportHeroAction(contentColor = MiuixTheme.colorScheme.onSurface)
                },
            )
            DuckPanel(
                contentPadding = PaddingValues(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                OverviewTitle(model = model)
                DetectorHairline()
                OverviewMetrics(metrics = model.metrics)
            }
        }
        return
    }
    val scheme = MaterialTheme.colorScheme
    val (containerColor, contentColor) = when (model.status.severity) {
        DetectionSeverity.DANGER -> scheme.errorContainer to scheme.onErrorContainer
        DetectionSeverity.WARNING, DetectionSeverity.ALL_CLEAR -> materialStatusTone(appearance.iconTint, scheme)
        DetectionSeverity.INFO -> scheme.surfaceContainerHigh to scheme.onSurface
    }
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Surface(
            onClick = onExportReport,
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
            color = containerColor,
            contentColor = contentColor,
        ) {
            Column {
                OverviewHero(model = model, appearance = appearance, contentColor = contentColor)
                ReportHeroFooter(
                    versionLabel = versionLabel,
                    buildTimeLabel = buildTimeLabel,
                    contentColor = contentColor,
                )
            }
        }
        DuckPanel(
            contentPadding = PaddingValues(20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OverviewTitle(model = model)
            DetectorHairline()
            OverviewMetrics(metrics = model.metrics)
        }
    }
}

/** Build metadata and the export affordance live in separate, full-width rows. */
@Composable
private fun ReportHeroFooter(
    versionLabel: String,
    buildTimeLabel: String,
    contentColor: Color,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        ReportHeroMetadata(
            versionLabel = versionLabel,
            buildTimeLabel = buildTimeLabel,
            contentColor = contentColor,
            modifier = Modifier.padding(start = 20.dp, end = 20.dp, top = 4.dp, bottom = 12.dp),
        )
        ReportHeroAction(contentColor = contentColor)
    }
}

@Composable
private fun ReportHeroMetadata(
    versionLabel: String,
    buildTimeLabel: String,
    contentColor: Color,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(5.dp)) {
        ReportMetaLine(icon = Icons.Rounded.Badge, label = versionLabel, color = contentColor.copy(alpha = 0.82f))
        ReportMetaLine(icon = Icons.Rounded.Schedule, label = buildTimeLabel, color = contentColor.copy(alpha = 0.72f))
    }
}

@Composable
private fun ReportHeroAction(contentColor: Color) {
    val isMiuix = LocalUiMode.current == UiMode.Miuix
    Column(modifier = Modifier.fillMaxWidth()) {
        HorizontalDivider(
            // The lower-right illustration occupies the rest of the MIUIX hero.
            // Do not draw a hairline through the glyph.
            modifier = Modifier.padding(start = 20.dp, end = if (isMiuix) 108.dp else 20.dp),
            color = contentColor.copy(alpha = 0.16f),
            thickness = Dp.Hairline,
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .padding(start = 20.dp, end = if (isMiuix) 106.dp else 20.dp, top = 11.dp, bottom = 11.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Icon(Icons.Rounded.FileDownload, contentDescription = null, modifier = Modifier.size(19.dp), tint = contentColor)
            WrapSafeText(
                text = stringResource(R.string.dashboard_export_report_hint),
                modifier = Modifier.weight(1f),
                style = if (isMiuix) MiuixTheme.textStyles.body2.copy(fontWeight = FontWeight.Medium)
                    else MaterialTheme.typography.labelLargeEmphasized,
                color = contentColor,
            )
            if (!isMiuix) {
                Icon(Icons.Rounded.ArrowForward, contentDescription = null, modifier = Modifier.size(18.dp), tint = contentColor.copy(alpha = 0.78f))
            }
        }
    }
}

@Composable
private fun ReportMetaLine(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(14.dp), tint = color)
        WrapSafeText(
            text = label,
            modifier = Modifier.weight(1f),
            style = if (LocalUiMode.current == UiMode.Miuix) MiuixTheme.textStyles.footnote1 else MaterialTheme.typography.bodySmall,
            color = color,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun OverviewHero(
    model: DashboardOverviewModel,
    appearance: StatusAppearance,
    contentColor: androidx.compose.ui.graphics.Color,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 20.dp, top = 20.dp, end = 20.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Box(
            modifier = Modifier
                .size(60.dp)
                .background(color = contentColor.copy(alpha = 0.12f), shape = CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = contentColor,
                modifier = Modifier.size(32.dp),
            )
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = model.headline,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.titleLargeEmphasized,
                color = contentColor,
            )
            WrapSafeText(
                text = model.summary,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodyMedium,
                color = contentColor.copy(alpha = 0.80f),
            )
        }
    }
}

/** The title is one line, or the scan's completion time over its duration. */
@Composable
private fun OverviewTitle(model: DashboardOverviewModel) {
    val lines = model.title.lines().filter { it.isNotBlank() }
    Row(
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        if (model.showTitleIcon) {
            Icon(
                imageVector = Icons.Outlined.Timer,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .padding(top = 2.dp)
                    .size(14.dp),
            )
        }
        Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
            lines.forEach { line ->
                WrapSafeText(
                    text = line,
                    style = DuckTypography.Footnote,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun OverviewMetrics(
    metrics: List<DashboardOverviewMetricModel>,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(IntrinsicSize.Min),
    ) {
        metrics.forEachIndexed { index, metric ->
            if (index > 0) {
                if (LocalUiMode.current == UiMode.Miuix) {
                    MiuixVerticalDivider(
                        modifier = Modifier.fillMaxHeight().padding(vertical = 4.dp),
                        thickness = Dp.Hairline,
                    )
                } else {
                    VerticalDivider(
                        modifier = Modifier.fillMaxHeight().padding(vertical = 4.dp),
                        thickness = Dp.Hairline,
                        color = DuckTheme.palette.separator,
                    )
                }
            }
            OverviewMetric(metric = metric, modifier = Modifier.weight(1f))
        }
    }
}

@Composable
private fun OverviewMetric(
    metric: DashboardOverviewMetricModel,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(metric.status)
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        WrapSafeText(
            text = metric.value,
            style = if (LocalUiMode.current == UiMode.Miuix) {
                MiuixTheme.textStyles.title2.copy(fontFeatureSettings = "tnum", fontWeight = FontWeight.Medium)
            } else {
                DuckTypography.Numeral
            },
            color = MaterialTheme.colorScheme.onSurface,
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .background(color = appearance.iconTint, shape = CircleShape),
            )
            WrapSafeText(
                text = metric.label,
                style = DuckTypography.PanelCaption,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
