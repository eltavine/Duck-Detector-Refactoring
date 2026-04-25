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

package com.eltavine.duckdetector.features.tee.ui.card

import android.content.ClipData
import android.content.ClipboardManager
import android.widget.Toast
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cable
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Details
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.components.DetectorCardFrame
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.tee.ui.TeeCertificatesDialog
import com.eltavine.duckdetector.features.tee.ui.TeeDetailsDialog
import com.eltavine.duckdetector.features.tee.ui.model.TeeCardModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeFactGroupModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeFactIcon
import com.eltavine.duckdetector.features.tee.ui.model.TeeFactRowModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionId
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeHeaderFactModel
import com.eltavine.duckdetector.features.tee.ui.model.TeeHighlightSignalModel
import com.eltavine.duckdetector.ui.theme.ShapeTokens

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TeeDetectorCard(
    model: TeeCardModel,
    showDetailsDialog: Boolean,
    showCertificatesDialog: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onFooterAction: (TeeFooterActionId) -> Unit,
    onDismissDetails: () -> Unit,
    onDismissCertificates: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (showDetailsDialog) {
        TeeDetailsDialog(
            exportText = model.exportText,
            certificateCount = model.certificateSummary.certificates.size,
            onDismiss = onDismissDetails,
        )
    }

    if (showCertificatesDialog) {
        TeeCertificatesDialog(
            label = model.certificateSummary.label,
            count = model.certificateSummary.count,
            certificates = model.certificateSummary.certificates,
            onDismiss = onDismissCertificates,
        )
    }

    DetectorCardFrame(
        title = model.title,
        subtitle = model.subtitle,
        status = model.status,
        verdict = model.verdict,
        summary = model.summary,
        leadingIcon = Icons.Rounded.Security,
        modifier = modifier,
        expanded = model.isExpanded,
        onExpandedChange = onExpandedChange,
        headerFacts = {
            TeeCollapsedOverview(model = model)
        },
        footerActions = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                TeeNetworkBanner(model = model)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    model.actions.forEach { action ->
                        TeeFooterButton(action = action, onClick = onFooterAction)
                    }
                }
            }
        },
    ) {
        if (model.highlightSignals.isNotEmpty()) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                model.highlightSignals.forEach { signal ->
                    TeeHighlightPill(signal = signal)
                }
            }
        }

        model.factGroups.forEach { group ->
            TeeFactGroup(group = group)
        }
    }
}

@Composable
private fun TeeCollapsedOverview(
    model: TeeCardModel,
) {
    val verdict = model.headerFacts.firstOrNull { it.label == "Verdict" } ?: return
    val score = model.headerFacts.firstOrNull { it.label == "Score" } ?: return
    val tier = model.headerFacts.firstOrNull { it.label == "Tier" } ?: return
    val trust = model.headerFacts.firstOrNull { it.label == "Trust" } ?: return

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        model.rkpBadgeLabel?.let { label ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
            ) {
                TeeRkpBadge(label = label)
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.Top,
        ) {
            TeeFactPairCard(
                primary = verdict,
                secondary = score,
                modifier = Modifier.weight(1f),
            )
            TeeFactPairCard(
                primary = tier,
                secondary = trust,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun TeeRkpBadge(
    label: String,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(DetectorStatus.allClear())
    Surface(
        modifier = modifier,
        color = appearance.iconTint.copy(alpha = 0.14f),
        shape = ShapeTokens.CornerFull,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.Verified,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = appearance.iconTint,
            )
        }
    }
}

@Composable
private fun TeeHeaderFactChip(
    fact: TeeHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerLarge,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Icon(
                    imageVector = appearance.icon,
                    contentDescription = null,
                    tint = appearance.iconTint,
                    modifier = Modifier.size(16.dp),
                )
                WrapSafeText(
                    text = fact.label,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            WrapSafeText(
                text = fact.value,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun TeeFactPairCard(
    primary: TeeHeaderFactModel,
    secondary: TeeHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            TeeFactPairRow(fact = primary)
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.42f),
                thickness = 1.dp,
            )
            TeeFactPairRow(fact = secondary)
        }
    }
}

@Composable
private fun TeeFactPairRow(
    fact: TeeHeaderFactModel,
) {
    val appearance = rememberStatusAppearance(fact.status)
    Column(
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(15.dp),
            )
            WrapSafeText(
                text = fact.label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        WrapSafeText(
            text = fact.value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
private fun TeeHighlightPill(
    signal: TeeHighlightSignalModel,
) {
    val appearance = rememberStatusAppearance(signal.status)
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = ShapeTokens.CornerFull,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(16.dp),
            )
            WrapSafeText(
                text = "${signal.label}: ${signal.value}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun TeeFactGroup(
    group: TeeFactGroupModel,
) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = ShapeTokens.CornerExtraLarge,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            WrapSafeText(
                text = group.title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                group.rows.forEachIndexed { index, row ->
                    TeeFactRow(row = row)
                    if (index < group.rows.lastIndex) {
                        HorizontalDivider(
                            color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.42f),
                            thickness = 1.dp,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun TeeFactRow(
    row: TeeFactRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.tee_timing_stack_clipboard_label)
    val copiedToast = stringResource(R.string.tee_timing_stack_copied_toast)
    val valueModifier = if (row.hiddenCopyText != null) {
        // timing 栈复制是故意做成“无显式 affordance”的双击隐藏入口，避免把正常读卡 UI 变成调试工具面板。
        // Timing stack copy is intentionally a no-affordance double-tap entry so the normal card UI does not turn into a visible debugging panel.
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                context.getSystemService(ClipboardManager::class.java)
                    ?.setPrimaryClip(ClipData.newPlainText(clipboardLabel, row.hiddenCopyText))
                Toast.makeText(context, copiedToast, Toast.LENGTH_SHORT).show()
            },
        )
    } else {
        Modifier
    }
    DetectorDetailRowBlock(
        label = row.label,
        value = row.value,
        status = row.status,
        statusIcon = iconFor(row.icon),
        verticalPadding = 0.dp,
        valueModifier = valueModifier,
    )
}

@Composable
private fun TeeNetworkBanner(model: TeeCardModel) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        shape = ShapeTokens.CornerLarge,
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            val appearance = rememberStatusAppearance(model.networkState.status)
            Icon(
                imageVector = appearance.icon,
                contentDescription = null,
                tint = appearance.iconTint,
                modifier = Modifier.size(18.dp),
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                WrapSafeText(
                    text = model.networkState.label,
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = model.networkState.summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun TeeFooterButton(
    action: TeeFooterActionModel,
    onClick: (TeeFooterActionId) -> Unit,
) {
    val label = action.counter?.let { "${action.label} (${it})" } ?: action.label
    if (action.id == TeeFooterActionId.RESCAN) {
        FilledTonalButton(
            onClick = { onClick(action.id) },
            enabled = action.enabled,
        ) {
            Icon(
                imageVector = Icons.Rounded.Refresh,
                contentDescription = null,
            )
            WrapSafeText(
                text = label,
                modifier = Modifier.padding(start = 8.dp),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    } else {
        OutlinedButton(
            onClick = { onClick(action.id) },
            enabled = action.enabled,
        ) {
            Icon(
                imageVector = when (action.id) {
                    TeeFooterActionId.DETAILS -> Icons.Rounded.Details
                    TeeFooterActionId.CERTIFICATES -> Icons.Rounded.VerifiedUser
                    TeeFooterActionId.RESCAN -> Icons.Rounded.Refresh
                },
                contentDescription = null,
            )
            WrapSafeText(
                text = label,
                modifier = Modifier.padding(start = 8.dp),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

private fun iconFor(icon: TeeFactIcon): ImageVector {
    return when (icon) {
        TeeFactIcon.TRUST -> Icons.Rounded.Security
        TeeFactIcon.CERTIFICATE -> Icons.Rounded.VerifiedUser
        TeeFactIcon.NETWORK -> Icons.Rounded.NetworkCheck
        TeeFactIcon.RKP -> Icons.Rounded.Hub
        TeeFactIcon.KEY -> Icons.Rounded.Key
        TeeFactIcon.BOOT -> Icons.Rounded.Lock
        TeeFactIcon.PATCH -> Icons.Rounded.Policy
        TeeFactIcon.DEVICE -> Icons.Rounded.Fingerprint
        TeeFactIcon.APP -> Icons.Rounded.Shield
        TeeFactIcon.AUTH -> Icons.Rounded.VpnKey
        TeeFactIcon.KEYSTORE -> Icons.Rounded.Cable
        TeeFactIcon.TIMING -> Icons.Rounded.Speed
        TeeFactIcon.STRONGBOX -> Icons.Rounded.Security
        TeeFactIcon.NATIVE -> Icons.Rounded.Memory
        TeeFactIcon.SOTER -> Icons.Rounded.VerifiedUser
        TeeFactIcon.WARNING -> Icons.Rounded.CrisisAlert
    }
}
