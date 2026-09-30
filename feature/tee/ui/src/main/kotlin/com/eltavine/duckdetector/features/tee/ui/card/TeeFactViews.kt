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

package com.eltavine.duckdetector.features.tee.ui.card

import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Cable
import androidx.compose.material.icons.rounded.CrisisAlert
import androidx.compose.material.icons.rounded.Fingerprint
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.rounded.VpnKey
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.AdaptiveShapeTokens
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.ui.R as CoreUiR
import com.eltavine.duckdetector.core.ui.components.DetectorDetailRowBlock
import com.eltavine.duckdetector.core.ui.components.DetectorFact
import com.eltavine.duckdetector.core.ui.components.DetectorFactPair
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.DetectorSectionFrame
import com.eltavine.duckdetector.core.ui.components.highestSectionSeverity
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.copyPlainTextToClipboard
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactGroupModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactIcon
import com.eltavine.duckdetector.features.tee.presentation.model.TeeFactRowModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHeaderFactModel
import com.eltavine.duckdetector.features.tee.presentation.model.TeeHighlightSignalModel
import com.eltavine.duckdetector.features.tee.ui.R
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue

@Composable
internal fun TeeFactPairCard(
    primary: TeeHeaderFactModel,
    secondary: TeeHeaderFactModel,
    modifier: Modifier = Modifier,
) {
    DetectorFactPair(
        primary = primary.asDetectorFact(),
        secondary = secondary.asDetectorFact(),
        modifier = modifier,
    )
}

private fun TeeHeaderFactModel.asDetectorFact() =
    DetectorFact(label = label, value = value, status = status)

@Composable
internal fun TeeHighlightPill(
    signal: TeeHighlightSignalModel,
) {
    val appearance = rememberStatusAppearance(signal.status)
    val containerColor = adaptiveValue(
        material = when (signal.status.severity) {
            DetectionSeverity.DANGER -> MaterialTheme.colorScheme.errorContainer
            DetectionSeverity.WARNING -> MaterialTheme.colorScheme.tertiaryContainer
            DetectionSeverity.ALL_CLEAR -> MaterialTheme.colorScheme.secondaryContainer
            DetectionSeverity.INFO -> MaterialTheme.colorScheme.surfaceContainerHigh
        },
        miuix = appearance.tintWash,
    )
    val contentColor = adaptiveValue(
        material = when (signal.status.severity) {
            DetectionSeverity.DANGER -> MaterialTheme.colorScheme.onErrorContainer
            DetectionSeverity.WARNING -> MaterialTheme.colorScheme.onTertiaryContainer
            DetectionSeverity.ALL_CLEAR -> MaterialTheme.colorScheme.onSecondaryContainer
            DetectionSeverity.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
        },
        miuix = MaterialTheme.colorScheme.onSurface,
    )
    val iconTint = adaptiveValue(material = contentColor, miuix = appearance.iconTint)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp)
            .background(
                color = containerColor,
                shape = AdaptiveShapeTokens.CornerMedium,
            )
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        DuckIcon(
            imageVector = appearance.icon,
            contentDescription = null,
            tint = iconTint,
            modifier = Modifier.size(15.dp),
        )
        WrapSafeText(
            text = "${signal.label}: ${signal.value}",
            style = DuckTypography.Caption,
            color = contentColor,
        )
    }
}

@Composable
internal fun TeeFactGroup(
    group: TeeFactGroupModel,
    stateKey: String,
    showDivider: Boolean,
) {
    // Both skins use the same section state and default-to-collapsed behavior.
    DetectorSectionFrame(
        title = group.title,
        icon = Icons.Rounded.Policy,
        stateKey = stateKey,
        showDivider = showDivider,
        severity = highestSectionSeverity(group.rows.map { it.status }),
    ) {
        group.rows.forEachIndexed { index, row ->
            TeeFactRow(row = row)
            if (index < group.rows.lastIndex) DetectorHairline()
        }
    }
}

@Composable
private fun TeeFactRow(
    row: TeeFactRowModel,
) {
    val context = LocalContext.current
    val clipboardLabel = stringResource(R.string.tee_diagnostic_clipboard_label)
    val copiedToast = stringResource(CoreUiR.string.tee_diagnostic_copied_toast)
    val copyText = row.hiddenCopyText
    val valueModifier = if (copyText != null) {
        // 诊断复制是故意做成“无显式 affordance”的双击隐藏入口，避免把正常读卡 UI 变成调试工具面板。
        // Diagnostic copy is intentionally a no-affordance double-tap entry so the normal card UI does not turn into a visible debugging panel.
        Modifier.combinedClickable(
            interactionSource = remember { MutableInteractionSource() },
            indication = null,
            onClick = {},
            onDoubleClick = {
                copyPlainTextToClipboard(context, clipboardLabel, copyText, copiedToast)
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
        valueModifier = valueModifier,
    )
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
