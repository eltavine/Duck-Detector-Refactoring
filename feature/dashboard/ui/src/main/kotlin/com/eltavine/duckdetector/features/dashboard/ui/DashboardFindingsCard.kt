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

package com.eltavine.duckdetector.features.dashboard.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedListItem
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.ui.components.AdaptiveSeverityTag
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardFindingModel
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent

private val FindingInset = 16.dp
private const val FINDING_DETAIL_MAX_LINES = 3

@Composable
internal fun DashboardFindingsCard(
    findings: List<DashboardFindingModel>,
) {
    AdaptiveContent(
        material = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(ListItemDefaults.SegmentedGap),
            ) {
                findings.forEachIndexed { index, finding ->
                    val baseShapes = ListItemDefaults.segmentedShapes(index, findings.size)
                    val shapes = if (findings.size == 1) {
                        baseShapes.copy(shape = MaterialTheme.shapes.large)
                    } else {
                        baseShapes
                    }
                    SegmentedListItem(
                        onClick = {},
                        modifier = Modifier.fillMaxWidth(),
                        shapes = shapes,
                        colors = ListItemDefaults.segmentedColors(
                            containerColor = MaterialTheme.colorScheme.surfaceBright,
                            disabledContainerColor = MaterialTheme.colorScheme.surfaceBright,
                            supportingContentColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        ),
                        verticalAlignment = Alignment.CenterVertically,
                        content = {
                            DashboardFindingContent(finding = finding)
                        },
                    )
                }
            }
        },
        miuix = {
            DuckPanel {
                findings.forEachIndexed { index, finding ->
                    DashboardFindingRow(finding = finding)
                    if (index < findings.lastIndex) {
                        DetectorHairline(
                            modifier = Modifier.padding(end = FindingInset),
                            startInset = FindingInset,
                        )
                    }
                }
            }
        },
    )
}

@Composable
private fun DashboardFindingRow(
    finding: DashboardFindingModel,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = FindingInset, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        DashboardFindingContent(finding = finding)
    }
}

@Composable
private fun DashboardFindingContent(
    finding: DashboardFindingModel,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            WrapSafeText(
                text = dashboardFindingTitle(finding),
                modifier = Modifier.weight(1f),
                style = DuckTypography.FindingEyebrow,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            AdaptiveSeverityTag(
                status = finding.status,
                label = findingSeverityLabel(finding),
            )
        }
        WrapSafeText(
            text = dashboardFindingHeadline(finding),
            modifier = Modifier.fillMaxWidth(),
            style = DuckTypography.PanelTitle,
            color = MaterialTheme.colorScheme.onSurface,
        )
        // The full evidence stays in the detector's card; a finding only points to it.
        WrapSafeText(
            text = dashboardFindingDetail(finding),
            modifier = Modifier.fillMaxWidth(),
            style = DuckTypography.PanelSupporting,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = FINDING_DETAIL_MAX_LINES,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun findingSeverityLabel(
    finding: DashboardFindingModel,
): String {
    return when (finding.status.severity) {
        DetectionSeverity.DANGER -> stringResource(R.string.dashboard_severity_high)
        DetectionSeverity.WARNING -> stringResource(R.string.dashboard_severity_medium)
        DetectionSeverity.INFO -> stringResource(R.string.dashboard_severity_check)
        DetectionSeverity.ALL_CLEAR -> stringResource(R.string.dashboard_severity_clear)
    }
}
