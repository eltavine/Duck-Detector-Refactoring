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

package com.eltavine.duckdetector.features.tee.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.VerifiedUser
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.capability.attestation.domain.TeeCertificateItem
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun TeeCertificatesDialog(
    show: Boolean,
    label: String,
    count: String,
    certificates: List<TeeCertificateItem>,
    onDismiss: () -> Unit,
) {
    TeeDialogFrame(
        show = show,
        title = "Certificate chain",
        subtitle = "Attestation certificates exposed by the current scan.",
        icon = Icons.Rounded.VerifiedUser,
        onDismiss = onDismiss,
    ) {
        if (certificates.isEmpty()) {
            TeeDialogSurface(tone = TeeDialogTone.Low) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 18.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    WrapSafeText(
                        text = "No certificates available",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = "This scan did not expose a valid attestation certificate chain.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    TeeCertificateSummaryRow(
                        label = label,
                        count = count,
                        leafLabel = certificates.firstOrNull()?.slotLabel ?: "None",
                        rootLabel = certificates.lastOrNull()?.slotLabel ?: "None",
                    )
                    certificates.forEachIndexed { index, certificate ->
                        TeeCertificateNode(
                            certificate = certificate,
                            isLast = index == certificates.lastIndex,
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun TeeCertificateSummaryRow(
    label: String,
    count: String,
    leafLabel: String,
    rootLabel: String,
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        TeeCertificateOverviewChip(
            icon = Icons.Rounded.Hub,
            label = label,
            value = "$count certs",
        )
        TeeCertificateOverviewChip(
            icon = Icons.Rounded.VerifiedUser,
            label = "Leaf",
            value = leafLabel,
        )
        TeeCertificateOverviewChip(
            icon = Icons.Rounded.Security,
            label = "Root",
            value = rootLabel,
        )
    }
}

@Composable
private fun TeeCertificateOverviewChip(
    icon: ImageVector,
    label: String,
    value: String,
) {
    TeeDialogSurface(tone = TeeDialogTone.Highest, cornerRadius = 12.dp) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            DuckIcon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(16.dp),
            )
            Column(verticalArrangement = Arrangement.spacedBy(1.dp)) {
                WrapSafeText(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = value,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
