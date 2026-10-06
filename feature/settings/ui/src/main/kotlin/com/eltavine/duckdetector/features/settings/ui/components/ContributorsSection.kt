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

package com.eltavine.duckdetector.features.settings.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.features.settings.ui.R
import io.github.xiaotong6666.uihelper.dialog.rememberRetainedDialogPayload
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode

@Composable
internal fun ContributorsSection(
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val miuix = LocalUiMode.current == UiMode.Miuix
    val contributorSnapshots = remember(context) { loadContributorSnapshots(context) }
    val authors = contributorSnapshots.map { snapshot ->
        AuthorProfile(
            login = snapshot.login,
            name = snapshot.name,
            profileUrl = snapshot.profileUrl,
            avatarAssetPath = snapshot.avatarAssetPath,
            contributionSummary = stringResource(summaryResIdForKey(snapshot.summaryKey)),
            contributions = snapshot.contributionKeys.mapNotNull(::authorContributionForKey),
        )
    }
    if (authors.isEmpty()) return

    var selectedLogin by rememberSaveable { mutableStateOf<String?>(null) }
    val selectedProfile = authors.firstOrNull { it.login == selectedLogin }
    val retainedProfile = rememberRetainedDialogPayload(
        value = selectedProfile,
        retainDuringExit = miuix,
    )

    SettingsSection(
        title = stringResource(R.string.author_wall_title),
        badge = authors.size.toString(),
        modifier = modifier,
    ) {
        DuckPanel(
            contentPadding = PaddingValues(18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            ContributorWallCanvas(
                authors = authors,
                onSelect = { selectedLogin = it.login },
            )
            WrapSafeText(
                text = stringResource(R.string.author_wall_hint),
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    retainedProfile.value?.let { profile ->
        AuthorDetailsDialog(
            show = selectedLogin != null,
            profile = profile,
            onDismiss = { selectedLogin = null },
            onDismissFinished = retainedProfile.onDismissFinished,
        )
    }
}
