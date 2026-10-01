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

package com.eltavine.duckdetector.core.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.Icon
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckPalette
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.materialStatusTone
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import io.github.xiaotong6666.uihelper.common.StatusTag
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** Uses the same compact MIUIX status tag as FuseHide's process and sync rows. */
@Composable
public fun MiuixStatusLabel(
    status: DetectorStatus,
    label: String,
    modifier: Modifier = Modifier,
) {
    val scheme = MiuixTheme.colorScheme
    val appearance = rememberStatusAppearance(status)
    val background = when (status.severity) {
        DetectionSeverity.DANGER -> scheme.error
        DetectionSeverity.WARNING, DetectionSeverity.ALL_CLEAR -> appearance.iconTint
        // A failed probe keeps its critical tint so it cannot pass for supporting information.
        DetectionSeverity.INFO -> if (status.infoKind == InfoKind.ERROR) appearance.iconTint else scheme.primary
    }
    // Keep severity-specific fills; every MIUIX status label uses opaque white text.
    val foreground = homeStatusLabelTextColor()
    StatusTag(
        label = label,
        modifier = modifier,
        backgroundColor = background,
        contentColor = foreground,
    )
}

internal fun homeStatusLabelTextColor(): Color = Color.White

@Composable
public fun StatusBadge(
    status: DetectorStatus,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(status)
    if (LocalUiMode.current == UiMode.Miuix) {
        Column(
            modifier = modifier.widthIn(max = 220.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            MiuixStatusLabel(status = status, label = appearance.label)
            appearance.metaLabel?.let { label ->
                MiuixText(
                    text = label,
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
        }
        return
    }

    val (containerColor, contentColor) = materialStatusColors(status, MaterialTheme.colorScheme, DuckTheme.palette)
    Column(
        modifier = modifier
            .widthIn(max = 220.dp)
            .background(color = containerColor, shape = MaterialTheme.shapes.medium)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = contentColor,
                modifier = Modifier.size(18.dp),
            )
            WrapSafeText(
                text = appearance.label,
                style = DuckTypography.CalloutEmphasized,
                color = contentColor,
            )
        }
        appearance.metaLabel?.let { metaLabel ->
            WrapSafeText(
                text = metaLabel,
                style = DuckTypography.PanelCaption,
                color = contentColor.copy(alpha = 0.76f),
            )
        }
    }
}

@Composable
public fun CompactStatusBadge(
    status: DetectorStatus,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(status)
    if (LocalUiMode.current == UiMode.Miuix) {
        MiuixStatusLabel(status = status, label = appearance.label, modifier = modifier)
        return
    }

    val (containerColor, contentColor) = materialStatusColors(status, MaterialTheme.colorScheme, DuckTheme.palette)
    Row(
        modifier = modifier
            .background(color = containerColor, shape = MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Icon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = contentColor,
            modifier = Modifier.size(14.dp),
        )
        WrapSafeText(
            text = appearance.label,
            style = MaterialTheme.typography.labelSmallEmphasized,
            color = contentColor,
        )
    }
}

/** KSU-style compact tonal tag, using Material's semantic colors rather than MIUIX fills. */
@Composable
public fun MaterialSeverityTag(
    status: DetectorStatus,
    label: String,
    modifier: Modifier = Modifier,
) {
    val (containerColor, contentColor) = materialStatusColors(status, MaterialTheme.colorScheme, DuckTheme.palette)
    Box(
        modifier = modifier
            .background(containerColor, MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 8.dp, vertical = 4.dp),
    ) {
        Text(label, color = contentColor, style = MaterialTheme.typography.labelSmallEmphasized)
    }
}

private fun materialStatusColors(
    status: DetectorStatus,
    scheme: ColorScheme,
    palette: DuckPalette,
): Pair<Color, Color> =
    if (status.infoKind == InfoKind.ERROR && status.severity == DetectionSeverity.INFO) {
        scheme.errorContainer to scheme.onErrorContainer
    } else {
        when (status.severity) {
            DetectionSeverity.DANGER -> scheme.errorContainer to scheme.onErrorContainer
            DetectionSeverity.WARNING -> materialStatusTone(palette.caution, scheme)
            DetectionSeverity.ALL_CLEAR -> materialStatusTone(palette.positive, scheme)
            DetectionSeverity.INFO -> scheme.surfaceContainerHigh to scheme.onSurfaceVariant
        }
    }
