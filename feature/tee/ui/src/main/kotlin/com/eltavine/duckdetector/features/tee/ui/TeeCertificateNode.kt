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

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.HorizontalDivider
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.capability.attestation.domain.TeeCertificateItem
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixDetailField
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixDetailSection
import io.github.xiaotong6666.uihelper.miuix.primitive.MiuixDetailSectionsCard

@Composable
internal fun TeeCertificateNode(
    certificate: TeeCertificateItem,
    isLast: Boolean,
) {
    val role = remember(certificate.slotLabel) { certificateRole(certificate.slotLabel) }
    val roleIcon = when (role) {
        TeeCertificateRole.LEAF -> Icons.Rounded.VpnKey
        TeeCertificateRole.INTERMEDIATE -> Icons.Rounded.Hub
        TeeCertificateRole.ROOT -> Icons.Rounded.Security
    }

    AdaptiveContent(
        material = {
            TeeCertificateNodeMaterial(
                certificate = certificate,
                isLast = isLast,
                role = role,
                roleIcon = roleIcon,
            )
        },
        miuix = {
            TeeCertificateNodeMiuix(
                certificate = certificate,
            )
        },
    )
}

@Composable
private fun TeeCertificateNodeMaterial(
    certificate: TeeCertificateItem,
    isLast: Boolean,
    role: TeeCertificateRole,
    roleIcon: ImageVector,
) {
    val accent = when (role) {
        TeeCertificateRole.LEAF -> MaterialTheme.colorScheme.primary
        TeeCertificateRole.INTERMEDIATE -> MaterialTheme.colorScheme.tertiary
        TeeCertificateRole.ROOT -> MaterialTheme.colorScheme.secondary
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Surface(
                color = accent.copy(alpha = 0.14f),
                shape = CircleShape,
            ) {
                DuckIcon(
                    imageVector = roleIcon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier
                        .padding(10.dp)
                        .size(18.dp),
                )
            }
            if (!isLast) {
                Box(
                    modifier = Modifier
                        .width(2.dp)
                        .height(64.dp)
                        .background(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.6f),
                            shape = ShapeTokens.CornerFull,
                        ),
                )
            }
        }

        TeeDialogSurface(tone = TeeDialogTone.Low, modifier = Modifier.weight(1f)) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 14.dp, vertical = 14.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        WrapSafeText(
                            text = certificate.slotLabel,
                            style = MaterialTheme.typography.labelLarge,
                            color = accent,
                        )
                        WrapSafeText(
                            text = certificate.subject,
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                }

                TeeCertificateGroup(
                    title = stringResource(R.string.tee_certificate_section_identity),
                    icon = Icons.Rounded.VerifiedUser,
                ) {
                    TeeCertificateField(
                        icon = Icons.Rounded.Security,
                        label = stringResource(R.string.tee_certificate_field_issuer),
                        value = certificate.issuer,
                    )
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f),
                        thickness = 1.dp,
                    )
                    TeeCertificateField(
                        icon = Icons.Rounded.Fingerprint,
                        label = stringResource(R.string.tee_certificate_field_serial_number),
                        value = certificate.serialNumber,
                    )
                }

                TeeCertificateGroup(
                    title = stringResource(R.string.tee_certificate_section_crypto),
                    icon = Icons.Rounded.Key,
                ) {
                    TeeCertificateField(
                        icon = Icons.Rounded.Key,
                        label = stringResource(R.string.tee_certificate_field_public_key),
                        value = certificate.publicKeySummary,
                    )
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.45f),
                        thickness = 1.dp,
                    )
                    TeeCertificateField(
                        icon = Icons.Rounded.VpnKey,
                        label = stringResource(R.string.tee_certificate_field_signature_algorithm),
                        value = certificate.signatureAlgorithm,
                    )
                }

                TeeCertificateGroup(
                    title = stringResource(R.string.tee_certificate_section_validity),
                    icon = Icons.Rounded.Schedule,
                ) {
                    TeeCertificateField(
                        icon = Icons.Rounded.Schedule,
                        label = stringResource(R.string.tee_certificate_field_active_window),
                        value = stringResource(
                            R.string.tee_certificate_active_window_value,
                            certificate.validFrom,
                            certificate.validUntil,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun TeeCertificateNodeMiuix(
    certificate: TeeCertificateItem,
) {
    MiuixDetailSectionsCard(
        sections = listOf(
            MiuixDetailSection(
                title = stringResource(R.string.tee_certificate_section_identity),
                icon = Icons.Rounded.VerifiedUser,
                fields = listOf(
                    MiuixDetailField(
                        stringResource(R.string.tee_certificate_field_subject),
                        certificate.subject,
                    ),
                    MiuixDetailField(
                        stringResource(R.string.tee_certificate_field_issuer),
                        certificate.issuer,
                    ),
                    MiuixDetailField(
                        stringResource(R.string.tee_certificate_field_serial_number),
                        certificate.serialNumber,
                    ),
                ),
            ),
            MiuixDetailSection(
                title = stringResource(R.string.tee_certificate_section_crypto),
                icon = Icons.Rounded.Key,
                fields = listOf(
                    MiuixDetailField(
                        stringResource(R.string.tee_certificate_field_public_key),
                        certificate.publicKeySummary,
                    ),
                    MiuixDetailField(
                        stringResource(R.string.tee_certificate_field_signature_algorithm),
                        certificate.signatureAlgorithm,
                    ),
                ),
            ),
            MiuixDetailSection(
                title = stringResource(R.string.tee_certificate_section_validity),
                icon = Icons.Rounded.Schedule,
                fields = listOf(
                    MiuixDetailField(
                        stringResource(R.string.tee_certificate_field_active_window),
                        stringResource(
                            R.string.tee_certificate_active_window_value,
                            certificate.validFrom,
                            certificate.validUntil,
                        ),
                    ),
                ),
            ),
        ),
    )
}

@Composable
private fun TeeCertificateGroup(
    title: String,
    icon: ImageVector,
    content: @Composable ColumnScope.() -> Unit,
) {
    TeeDialogSurface(tone = TeeDialogTone.High, cornerRadius = 12.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                TeeDialogSurface(tone = TeeDialogTone.Highest, cornerRadius = 12.dp) {
                    DuckIcon(
                        imageVector = icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier
                            .padding(8.dp)
                            .size(16.dp),
                    )
                }
                WrapSafeText(
                    text = title,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp),
                content = content,
            )
        }
    }
}

@Composable
private fun TeeCertificateField(
    icon: ImageVector,
    label: String,
    value: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        TeeDialogSurface(tone = TeeDialogTone.Highest, cornerRadius = 12.dp) {
            DuckIcon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .padding(8.dp)
                    .size(16.dp),
            )
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(3.dp),
        ) {
            WrapSafeText(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            WrapSafeText(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

private enum class TeeCertificateRole {
    LEAF,
    INTERMEDIATE,
    ROOT,
}

private fun certificateRole(slotLabel: String): TeeCertificateRole {
    val normalized = slotLabel.lowercase()
    return when {
        "root" in normalized -> TeeCertificateRole.ROOT
        "generated key" in normalized -> TeeCertificateRole.LEAF
        "attestation" in normalized -> TeeCertificateRole.LEAF
        "leaf" in normalized -> TeeCertificateRole.LEAF
        else -> TeeCertificateRole.INTERMEDIATE
    }
}
