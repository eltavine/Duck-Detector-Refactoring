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

package com.eltavine.duckdetector.core.ui.presentation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.GppBad
import androidx.compose.material.icons.rounded.TipsAndUpdates
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.model.InfoKind

@Immutable
data class StatusAppearance(
    val label: String,
    val metaLabel: String?,
    val icon: ImageVector,
    val iconTint: Color,
)

private val SupportIconTint = Color(0xFF757575)
private val SafeIconTint = Color(0xFF2E7D32)
private val WarningIconTint = Color(0xFFB28704)
private val ErrorIconTint = Color(0xFFC62828)

@Composable
fun rememberStatusAppearance(status: DetectorStatus): StatusAppearance {
    val infoLabel = stringResource(R.string.status_info)
    val infoErrorLabel = stringResource(R.string.status_info_error)
    val infoSupportLabel = stringResource(R.string.status_info_support)
    val allClearLabel = stringResource(R.string.status_all_clear)
    val warningLabel = stringResource(R.string.status_warning)
    val dangerLabel = stringResource(R.string.status_danger)

    return when (status.severity) {
        DetectionSeverity.INFO -> {
            val isError = status.infoKind == InfoKind.ERROR

            StatusAppearance(
                label = infoLabel,
                metaLabel = if (isError) infoErrorLabel else infoSupportLabel,
                icon = if (isError) Icons.Rounded.ErrorOutline else Icons.Rounded.TipsAndUpdates,
                iconTint = if (isError) ErrorIconTint else SupportIconTint,
            )
        }

        DetectionSeverity.ALL_CLEAR -> StatusAppearance(
            label = allClearLabel,
            metaLabel = null,
            icon = Icons.Rounded.Verified,
            iconTint = SafeIconTint,
        )

        DetectionSeverity.WARNING -> StatusAppearance(
            label = warningLabel,
            metaLabel = null,
            icon = Icons.Rounded.Warning,
            iconTint = WarningIconTint,
        )

        DetectionSeverity.DANGER -> StatusAppearance(
            label = dangerLabel,
            metaLabel = null,
            icon = Icons.Rounded.GppBad,
            iconTint = ErrorIconTint,
        )
    }
}
