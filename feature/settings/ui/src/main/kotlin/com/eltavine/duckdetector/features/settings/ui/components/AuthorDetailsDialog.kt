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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.core.ui.theme.ShapeTokens
import com.eltavine.duckdetector.features.settings.ui.R
import com.eltavine.duckdetector.core.ui.R as CoreUiR

@Composable
internal fun AuthorDetailsDialog(
    profile: AuthorProfile,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = ShapeTokens.CornerExtraLarge,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        text = {
            Column(
                modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                AuthorAvatar(profile = profile, modifier = Modifier.size(104.dp))
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    WrapSafeText(
                        text = profile.name,
                        style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    if (profile.name != profile.login) {
                        WrapSafeText(
                            text = "@${profile.login}",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
                WrapSafeText(
                    text = profile.contributionSummary,
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (profile.contributions.isNotEmpty()) {
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        profile.contributions.forEach { contribution ->
                            ContributionBadge(contribution)
                        }
                    }
                }
            }
        },
        confirmButton = {
            FilledTonalButton(onClick = { openExternalUri(context, profile.profileUrl) }) {
                Icon(
                    painter = painterResource(CoreUiR.drawable.ic_github),
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                WrapSafeText(
                    text = stringResource(R.string.author_view_github),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                WrapSafeText(text = stringResource(R.string.author_details_close))
            }
        },
    )
}

@Composable
private fun ContributionBadge(contribution: AuthorContribution) {
    Surface(
        shape = ShapeTokens.CornerFull,
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = contribution.icon,
                contentDescription = null,
                tint = contribution.tint,
                modifier = Modifier.size(18.dp),
            )
            WrapSafeText(
                text = contribution.label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}
