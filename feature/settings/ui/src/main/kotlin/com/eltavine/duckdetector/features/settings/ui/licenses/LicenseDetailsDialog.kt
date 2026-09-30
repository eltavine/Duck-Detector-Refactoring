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

package com.eltavine.duckdetector.features.settings.ui.licenses

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material3.Button
import com.eltavine.duckdetector.core.ui.components.DuckIcon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.Hyphens
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.eltavine.duckdetector.core.designsystem.components.DuckButtonDefaults
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.designsystem.theme.AdaptiveShapeTokens
import com.eltavine.duckdetector.core.ui.components.DetectorHairline
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.openExternalUri
import com.eltavine.duckdetector.features.settings.ui.R
import com.mikepenz.aboutlibraries.entity.Library
import com.mikepenz.aboutlibraries.ui.compose.util.author
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import top.yukonga.miuix.kmp.basic.Button as MiuixButton
import top.yukonga.miuix.kmp.basic.ButtonDefaults as MiuixButtonDefaults
import top.yukonga.miuix.kmp.basic.Card as MiuixCard
import top.yukonga.miuix.kmp.basic.HorizontalDivider as MiuixDivider
import top.yukonga.miuix.kmp.basic.Text as MiuixText
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType
import top.yukonga.miuix.kmp.window.WindowDialog

private val DialogInset = 20.dp
private val GroupInset = 16.dp

/**
 * The details of one library: who publishes it, where its project lives and the full text of every
 * license it declares. The identity stays pinned above the scrolling license text, so a long
 * license never scrolls the library's name out of view.
 */
@Composable
internal fun LicenseDetailsDialog(
    show: Boolean,
    library: Library,
    onDismiss: () -> Unit,
    onDismissFinished: () -> Unit = {},
) {
    if (LocalUiMode.current == UiMode.Miuix) {
        LicenseDetailsMiuix(
            show = show,
            library = library,
            onDismiss = onDismiss,
            onDismissFinished = onDismissFinished,
        )
        return
    }
    if (!show) return
    val scrollState = rememberScrollState()

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Column(
            modifier = Modifier
                .padding(horizontal = DialogInset, vertical = 32.dp)
                .widthIn(max = 560.dp)
                .fillMaxWidth()
                .background(
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                    shape = MaterialTheme.shapes.extraLarge,
                )
                .padding(top = 24.dp, bottom = DialogInset),
        ) {
            LicenseDialogHeader(
                library = library,
                modifier = Modifier.padding(horizontal = DialogInset),
            )
            DetectorHairline(
                modifier = Modifier
                    .padding(top = 18.dp)
                    .alpha(if (scrollState.canScrollBackward) 1f else 0f),
            )
            Column(
                modifier = Modifier
                    .weight(1f, fill = false)
                    .verticalScroll(scrollState)
                    .padding(horizontal = GroupInset, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                library.description?.takeIf { it.isNotBlank() }?.let { description ->
                    WrapSafeText(
                        text = description,
                        modifier = Modifier.padding(horizontal = 4.dp),
                        style = DuckTypography.Callout,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                LibraryProjectLink(library = library)
                library.licenses.forEach { license ->
                    LicenseTextGroup(license = license)
                }
            }
            DetectorHairline(
                modifier = Modifier.alpha(if (scrollState.canScrollForward) 1f else 0f),
            )
            Button(
                onClick = onDismiss,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = DialogInset, end = DialogInset, top = 16.dp),
                colors = DuckButtonDefaults.filledColors(),
                contentPadding = DuckButtonDefaults.LargeContentPadding,
            ) {
                WrapSafeText(
                    text = stringResource(R.string.licenses_dialog_close),
                    style = DuckTypography.Headline,
                )
            }
        }
    }
}

@Composable
private fun LicenseDetailsMiuix(
    show: Boolean,
    library: Library,
    onDismiss: () -> Unit,
    onDismissFinished: () -> Unit,
) {
    val context = LocalContext.current
    val website = library.website?.takeIf { it.isNotBlank() }
    val projectUrl = website ?: library.scm?.url?.takeIf { it.isNotBlank() }
    // Licenses is a secondary NavDisplay destination above the main MIUIX Scaffold.
    // OverlayDialog registers in the root Scaffold's popup host, behind that destination;
    // WindowDialog owns a platform window and remains visible above the licenses route.
    WindowDialog(
        show = show,
        title = library.name,
        summary = library.author.takeIf { it.isNotBlank() },
        onDismissRequest = onDismiss,
        onDismissFinished = onDismissFinished,
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            library.artifactVersion?.takeIf { it.isNotBlank() }?.let { version ->
                LicensePill(text = stringResource(R.string.licenses_dialog_version, version), version = true)
            }
            Column(
                modifier = Modifier.fillMaxWidth().heightIn(max = 360.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                library.description?.takeIf { it.isNotBlank() }?.let { description ->
                    MiuixText(
                        text = description,
                        style = MiuixTheme.textStyles.body2,
                        color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                    )
                }
                if (projectUrl != null) {
                    MiuixCard(
                        modifier = Modifier.fillMaxWidth(),
                        insideMargin = androidx.compose.foundation.layout.PaddingValues(14.dp),
                        pressFeedbackType = PressFeedbackType.None,
                        showIndication = true,
                        onClick = { openExternalUri(context, projectUrl) },
                    ) {
                        MiuixText(
                            text = stringResource(
                                if (website != null) R.string.licenses_dialog_home_page
                                else R.string.licenses_dialog_source_repo,
                            ),
                            style = MiuixTheme.textStyles.headline1,
                        )
                        MiuixText(
                            text = projectUrl,
                            style = MiuixTheme.textStyles.footnote1,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                library.licenses.forEach { license ->
                    MiuixCard(
                        modifier = Modifier.fillMaxWidth(),
                        insideMargin = androidx.compose.foundation.layout.PaddingValues(14.dp),
                        pressFeedbackType = PressFeedbackType.None,
                        showIndication = !license.url.isNullOrBlank(),
                        onClick = license.url?.takeIf { it.isNotBlank() }?.let { url ->
                            { openExternalUri(context, url) }
                        },
                    ) {
                        MiuixText(text = license.name, style = MiuixTheme.textStyles.headline1)
                        MiuixDivider(modifier = Modifier.padding(vertical = 8.dp))
                        SelectionContainer {
                            MiuixText(
                                text = license.licenseContent?.trim()?.takeIf { it.isNotEmpty() }
                                    ?: stringResource(R.string.licenses_dialog_no_license_text),
                                style = MiuixTheme.textStyles.footnote1,
                                color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                            )
                        }
                    }
                }
            }
            MiuixButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth(),
                colors = MiuixButtonDefaults.buttonColorsPrimary(),
            ) {
                MiuixText(text = stringResource(R.string.licenses_dialog_close))
            }
        }
    }
}

@Composable
private fun LicenseDialogHeader(
    library: Library,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(
            modifier = Modifier
                .padding(bottom = 6.dp)
                .size(56.dp)
                .background(color = DuckTheme.palette.groupedInset, shape = AdaptiveShapeTokens.CornerLarge),
            contentAlignment = Alignment.Center,
        ) {
            DuckIcon(
                imageVector = Icons.Rounded.Description,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.size(28.dp),
            )
        }
        // A library's name is a proper name: it may wrap between words but is never hyphenated.
        Text(
            text = library.name,
            style = DuckTypography.Title3.copy(hyphens = Hyphens.None),
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.Center,
        )
        library.author.takeIf { it.isNotBlank() }?.let { author ->
            WrapSafeText(
                text = author,
                style = DuckTypography.Callout,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        if (library.uniqueId.isNotBlank()) {
            WrapSafeText(
                text = library.uniqueId,
                style = DuckTypography.Footnote.copy(fontFamily = FontFamily.Monospace),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        library.artifactVersion?.takeIf { it.isNotBlank() }?.let { version ->
            LicensePill(
                text = stringResource(R.string.licenses_dialog_version, version),
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}
