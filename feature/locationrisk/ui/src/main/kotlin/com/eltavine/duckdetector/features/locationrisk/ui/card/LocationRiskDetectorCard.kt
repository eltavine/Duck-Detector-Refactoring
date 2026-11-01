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

package com.eltavine.duckdetector.features.locationrisk.ui.card

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.LocationOn
import androidx.compose.material.icons.rounded.Info
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.*
import com.eltavine.duckdetector.features.locationrisk.presentation.model.LocationRiskCardModel

@Composable
internal fun LocationRiskDetectorCard(model: LocationRiskCardModel, modifier: Modifier = Modifier) {
    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.LocationOn,
        modifier = modifier,
        headerFacts = {
            Row(
                modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.Top,
            ) {
                model.headerFacts.chunked(2).forEach { pair ->
                    DetectorFactPair(
                        primary = DetectorFact(pair[0].label, pair[0].value, pair[0].status),
                        secondary = DetectorFact(pair[1].label, pair[1].value, pair[1].status),
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        },
    ) {
        DetectorSectionGroup {
            model.sections.forEachIndexed { index, section ->
                item(visible = section.rows.isNotEmpty()) {
                    DetectorSectionFrame(
                        stateKey = "locationrisk.${section.key}",
                        title = section.title,
                        icon = Icons.Rounded.Info,
                        severity = highestSectionSeverity(section.rows.map { it.status }),
                        showDivider = index < model.sections.lastIndex,
                    ) {
                        section.rows.forEachIndexed { rowIndex, row ->
                            DetectorDetailRowBlock(label = row.label, value = row.value, status = row.status, detail = row.detail)
                            if (rowIndex < section.rows.lastIndex) DetectorHairline()
                        }
                    }
                }
            }
        }
    }
}
