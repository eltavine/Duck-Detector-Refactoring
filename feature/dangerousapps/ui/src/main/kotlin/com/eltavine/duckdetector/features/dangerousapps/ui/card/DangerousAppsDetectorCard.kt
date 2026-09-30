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

package com.eltavine.duckdetector.features.dangerousapps.ui.card

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.components.ContextLine
import com.eltavine.duckdetector.core.ui.components.DetectorActionButton
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorFact
import com.eltavine.duckdetector.core.ui.components.DetectorFactPair
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.DetectorSectionGroup
import com.eltavine.duckdetector.core.ui.components.toSectionSeverity
import com.eltavine.duckdetector.core.ui.model.ContextItemModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsCardModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFact
import com.eltavine.duckdetector.features.dangerousapps.presentation.model.DangerousAppsHeaderFactModel
import com.eltavine.duckdetector.features.dangerousapps.ui.DangerousAppsTargetsDialog
import com.eltavine.duckdetector.features.dangerousapps.ui.R

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun DangerousAppsDetectorCard(
    model: DangerousAppsCardModel,
    modifier: Modifier = Modifier,
) {
    var showTargetsDialog by rememberSaveable { mutableStateOf(false) }

    DangerousAppsTargetsDialog(
        show = showTargetsDialog,
        targets = model.targetApps,
        onDismiss = { showTargetsDialog = false },
    )

    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Apps,
        modifier = modifier,
        headerFacts = {
            DangerousAppsOverview(model = model)
        },
        footerActions = {
            DetectorActionButton(
                label = stringResource(R.string.target_app_list_view, model.targetApps.size),
                icon = Icons.Rounded.Apps,
                onClick = { showTargetsDialog = true },
                modifier = Modifier.fillMaxWidth(),
            )
        },
    ) {
        model.hmaAlert?.let { hmaAlert ->
            DangerousAppsHmaSection(
                alert = hmaAlert,
            )
        }

        DetectorSectionGroup {
            item {
                DetectorSectionFrame(
                    title = stringResource(R.string.dangerousapps_section_packages),
                    icon = Icons.Rounded.Shield,
                    severity = model.packageSectionSeverity?.toSectionSeverity(),
                ) {
                    DangerousAppsPackageSection(model = model)
                }
            }
            item {
                DetectorSectionFrame(
                    title = stringResource(R.string.dangerousapps_section_context),
                    icon = Icons.Rounded.Search,
                    showDivider = false,
                ) {
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        model.context.forEach { contextItem ->
                            ContextLine(item = ContextItemModel(label = contextItem.label, value = contextItem.value))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DangerousAppsOverview(
    model: DangerousAppsCardModel,
) {
    val targets = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.TARGETS } ?: return
    val packageManager = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.PM } ?: return
    val hits = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.HITS } ?: return
    val hidden = model.headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.HIDDEN } ?: return

    Row(
        modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        verticalAlignment = Alignment.Top,
    ) {
        DangerousAppsFactPairCard(
            primary = targets,
            secondary = packageManager,
            modifier = Modifier.weight(1f),
        )
        DangerousAppsFactPairCard(
            primary = hits,
            secondary = hidden,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun DangerousAppsFactPairCard(
    primary: DangerousAppsHeaderFactModel,
    secondary: DangerousAppsHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun DangerousAppsHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)
