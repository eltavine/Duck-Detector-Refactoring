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
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Email
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material3.LocalContentColor
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.R as CoreUiR
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.settings.ui.R
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveFilledIconButton
import com.eltavine.duckdetector.core.ui.components.DuckIcon

private const val ABOUT_WEBSITE = "eltavine.com"
private const val ABOUT_EMAIL = "me@eltavine.com"
private const val ABOUT_GITHUB_URL = "https://github.com/eltavine/Duck-Detector-Refactoring"

@Composable
internal fun AboutLinks(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally),
    ) {
        AboutLinkButton(onClick = { openExternalUri(context, "https://$ABOUT_WEBSITE") }) {
            DuckIcon(
                imageVector = Icons.Rounded.Language,
                contentDescription = stringResource(R.string.about_label_website),
                tint = aboutMiuixIconColor(),
            )
        }
        AboutLinkButton(onClick = { openExternalUri(context, "mailto:$ABOUT_EMAIL") }) {
            DuckIcon(
                imageVector = Icons.Rounded.Email,
                contentDescription = stringResource(R.string.about_label_email),
                tint = aboutMiuixIconColor(),
            )
        }
        AboutLinkButton(onClick = { openExternalUri(context, ABOUT_GITHUB_URL) }) {
            DuckIcon(
                painter = painterResource(CoreUiR.drawable.ic_github),
                contentDescription = stringResource(CoreUiR.string.social_github),
                tint = aboutMiuixIconColor(),
            )
        }
    }
}

@Composable
private fun AboutLinkButton(
    onClick: () -> Unit,
    content: @Composable () -> Unit,
) {
    AdaptiveFilledIconButton(
        onClick = onClick,
        content = content,
    )
}
