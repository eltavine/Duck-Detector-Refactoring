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

package com.eltavine.duckdetector.ui.shell

import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckButtonDefaults
import com.eltavine.duckdetector.core.designsystem.theme.ContinuousCornerShape
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.MotionTokens
import com.eltavine.duckdetector.core.designsystem.theme.ShapeTokens
import com.eltavine.duckdetector.core.ui.components.WrapSafeText

private val IconTileShape = ContinuousCornerShape(11.dp)

@Composable
internal fun StartupPolicyCard(
    card: StartupPolicyCardUi,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = DuckTheme.palette.groupedSurface,
                shape = ShapeTokens.CornerExtraLargeIncreased,
            )
            .animateContentSize(MotionTokens.smoothSpring())
            .padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .background(color = DuckTheme.palette.groupedInset, shape = IconTileShape),
                contentAlignment = Alignment.Center,
            ) {
                DuckIcon(
                    imageVector = card.icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.size(22.dp),
                )
            }
            WrapSafeText(
                text = card.title,
                modifier = Modifier.weight(1f),
                style = DuckTypography.Headline,
                color = MaterialTheme.colorScheme.onSurface,
            )
            PolicyStatusCapsule(
                label = card.statusLabel,
                tone = card.tone,
            )
        }

        Column(
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            WrapSafeText(
                text = card.headline,
                style = DuckTypography.Body,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = card.detail,
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        PolicyActions(card = card)
    }
}

/** A card's state. One that still needs a decision is inverted, so it reads first in either theme. */
@Composable
private fun PolicyStatusCapsule(
    label: String,
    tone: StartupPolicyTone,
) {
    val colorScheme = MaterialTheme.colorScheme
    val inset = DuckTheme.palette.groupedInset
    val (container, content) = when (tone) {
        StartupPolicyTone.REQUIRED -> colorScheme.onSurface to colorScheme.surface
        StartupPolicyTone.READY -> inset to colorScheme.onSurface
        StartupPolicyTone.ACKNOWLEDGED,
        StartupPolicyTone.SUPPORT -> inset to colorScheme.onSurfaceVariant
    }
    WrapSafeText(
        text = label,
        modifier = Modifier
            .background(color = container, shape = ShapeTokens.CornerFull)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        style = DuckTypography.Caption,
        color = content,
    )
}

private class PolicyAction(
    val label: String,
    val onClick: () -> Unit,
)

/**
 * The card's choices. A required card leads with its recommended action above a quieter way out.
 * An optional consent gives both answers the same weight, so neither is nudged.
 */
@Composable
private fun PolicyActions(
    card: StartupPolicyCardUi,
) {
    val primary = card.primaryActionLabel?.let { label ->
        card.onPrimaryAction?.let { onClick -> PolicyAction(label, onClick) }
    }
    val secondary = card.secondaryActionLabel?.let { label ->
        card.onSecondaryAction?.let { onClick -> PolicyAction(label, onClick) }
    }
    if (primary == null && secondary == null) {
        return
    }

    if (card.requiresAction) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            primary?.let { action ->
                Button(
                    onClick = action.onClick,
                    modifier = Modifier.fillMaxWidth(),
                    colors = DuckButtonDefaults.filledColors(),
                    contentPadding = DuckButtonDefaults.LargeContentPadding,
                ) {
                    WrapSafeText(
                        text = action.label,
                        style = DuckTypography.Headline,
                        textAlign = TextAlign.Center,
                    )
                }
            }
            secondary?.let { action ->
                TextButton(
                    onClick = action.onClick,
                    modifier = Modifier.fillMaxWidth(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                ) {
                    WrapSafeText(
                        text = action.label,
                        style = DuckTypography.CalloutEmphasized,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    } else {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min)
                .padding(top = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            listOfNotNull(secondary, primary).forEach { action ->
                Button(
                    onClick = action.onClick,
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxHeight(),
                    colors = DuckButtonDefaults.tonalColors(),
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 12.dp),
                ) {
                    WrapSafeText(
                        text = action.label,
                        style = DuckTypography.CalloutEmphasized,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}
