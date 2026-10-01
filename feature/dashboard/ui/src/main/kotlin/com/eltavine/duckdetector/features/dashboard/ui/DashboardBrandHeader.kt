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

package com.eltavine.duckdetector.features.dashboard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.basic.IconButton as MiuixIconButton
import com.eltavine.duckdetector.core.ui.R as CoreUiR

/** Standalone dashboard fallback; hosted pages place branding in their native top bars. */
@Composable
internal fun BrandHeader(showTitle: Boolean = true) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            MaterialAppIcon()
            Spacer(modifier = Modifier.weight(1f))
            DashboardTelegramAction()
        }
        if (showTitle) {
            WrapSafeText(
                text = stringResource(CoreUiR.string.app_name),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 12.dp)
                    .semantics { heading() },
                style = DuckTypography.PageTitle,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

// The logo is a one-color glyph tinted with the text color, so it inverts with the theme: black on
// the light tile, white on the dark one.
@Composable
private fun MaterialAppIcon(modifier: Modifier = Modifier, size: androidx.compose.ui.unit.Dp = 56.dp) {
    Box(
        modifier = modifier
            .size(size)
            // Preserve the original 56dp/14dp tile proportions in the compact bar.
            .background(color = DuckTheme.palette.groupedSurface, shape = RoundedCornerShape(size / 4)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            painter = painterResource(R.drawable.ic_duck_logo),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.size(size * (34f / 56f)),
        )
    }
}

/** App-owned top bar mark: preserve Material's tile and use only the duck line art on MIUIX. */
@Composable
public fun DashboardTopBarBrandIcon() {
    if (LocalUiMode.current == UiMode.Miuix) {
        Icon(
            painter = painterResource(R.drawable.ic_duck_logo),
            contentDescription = null,
            tint = MiuixTheme.colorScheme.onSurface,
            modifier = Modifier.size(30.dp),
        )
    } else {
        MaterialAppIcon(size = 40.dp)
    }
}

/** Telegram's existing circle/plane glyph without a second background in MIUIX mode. */
@Composable
public fun DashboardTelegramAction() {
    val context = LocalContext.current
    val onClick: () -> Unit = { openExternalUri(context, "https://t.me/duck_detector") }
    if (LocalUiMode.current == UiMode.Miuix) {
        MiuixIconButton(onClick = onClick) {
            Icon(
                painter = painterResource(CoreUiR.drawable.ic_telegram),
                contentDescription = stringResource(CoreUiR.string.social_telegram),
                modifier = Modifier.size(26.dp),
                tint = MiuixTheme.colorScheme.onSurface,
            )
        }
    } else {
        FilledIconButton(
            onClick = onClick,
            colors = IconButtonDefaults.filledIconButtonColors(
                containerColor = DuckTheme.palette.groupedSurface,
                contentColor = MaterialTheme.colorScheme.primary,
            ),
        ) {
            Icon(
                painter = painterResource(CoreUiR.drawable.ic_telegram),
                contentDescription = stringResource(CoreUiR.string.social_telegram),
                modifier = Modifier.size(20.dp),
            )
        }
    }
}
