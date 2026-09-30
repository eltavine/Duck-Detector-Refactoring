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

package com.eltavine.duckdetector.features.settings.ui.licenses

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.OpenInNew
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.Gavel
import androidx.compose.material.icons.rounded.Language
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.AdaptiveShapeTokens
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.settings.ui.R
import com.mikepenz.aboutlibraries.entity.Library
import com.mikepenz.aboutlibraries.entity.License

private val GroupInset = 16.dp

@Composable
internal fun LibraryProjectLink(library: Library) {
    val context = LocalContext.current
    val website = library.website?.takeIf { it.isNotBlank() }
    val url = website ?: library.scm?.url?.takeIf { it.isNotBlank() } ?: return
    LinkRow(
        icon = if (website != null) Icons.Rounded.Language else Icons.Rounded.Code,
        label = stringResource(
            if (website != null) R.string.licenses_dialog_home_page else R.string.licenses_dialog_source_repo,
        ),
        url = url,
        onClick = { openExternalUri(context, url) },
        modifier = Modifier
            .clip(AdaptiveShapeTokens.CornerLarge)
            .background(color = DuckTheme.palette.groupedInset),
    )
}

@Composable
internal fun LicenseTextGroup(license: License) {
    val context = LocalContext.current
    val url = license.url?.takeIf { it.isNotBlank() }
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(AdaptiveShapeTokens.CornerLarge)
            .background(color = DuckTheme.palette.groupedInset),
    ) {
        if (url != null) {
            LinkRow(
                icon = Icons.Rounded.Gavel,
                label = license.name,
                url = url,
                onClick = { openExternalUri(context, url) },
            )
        } else {
            LicenseNameRow(name = license.name)
        }
        DetectorHairline(startInset = GroupInset)
        SelectionContainer {
            WrapSafeText(
                text = license.licenseContent?.trim()?.takeIf { it.isNotEmpty() }
                    ?: stringResource(R.string.licenses_dialog_no_license_text),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = GroupInset, vertical = 14.dp),
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LinkRow(
    icon: ImageVector,
    label: String,
    url: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = GroupInset, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        DuckIcon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = label,
                style = DuckTypography.CalloutEmphasized,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = url,
                style = DuckTypography.Footnote,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        DuckIcon(
            imageVector = Icons.AutoMirrored.Rounded.OpenInNew,
            contentDescription = stringResource(R.string.licenses_dialog_open),
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(18.dp),
        )
    }
}

@Composable
private fun LicenseNameRow(name: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = GroupInset, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        DuckIcon(
            imageVector = Icons.Rounded.Gavel,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp),
        )
        WrapSafeText(
            text = name,
            style = DuckTypography.CalloutEmphasized,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
