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

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.features.settings.ui.R
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveCircularProgressIndicator
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveSummaryCard
import io.github.xiaotong6666.uihelper.adaptive.adaptiveVerticalScrollFeedback
import io.github.xiaotong6666.uihelper.chrome.DetailPageHost
import io.github.xiaotong6666.uihelper.dialog.rememberRetainedDialogPayload
import io.github.xiaotong6666.uihelper.mode.LocalUiMode
import io.github.xiaotong6666.uihelper.mode.UiMode
import com.mikepenz.aboutlibraries.entity.Library
import com.mikepenz.aboutlibraries.ui.compose.LibraryDefaults
import com.mikepenz.aboutlibraries.ui.compose.m3.chipColors
import com.mikepenz.aboutlibraries.ui.compose.m3.LibrariesContainer
import com.mikepenz.aboutlibraries.ui.compose.m3.libraryColors
import com.mikepenz.aboutlibraries.ui.compose.produceLibraries

@Composable
fun OpenSourceLicensesScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val resources = LocalResources.current
    val libraries by produceLibraries {
        AboutLibrariesJsonOverrides.apply(
            resources
                .openRawResource(R.raw.aboutlibraries)
                .bufferedReader()
                .use { it.readText() },
        )
    }
    val libraryCount = libraries?.libraries?.size
    val miuixLibraries = remember(libraries) { libraries?.libraries?.sortedBy { it.name.lowercase() }.orEmpty() }
    var selectedLibrary by remember { mutableStateOf<Library?>(null) }
    val retainedLibrary = rememberRetainedDialogPayload(selectedLibrary)

    if (LocalUiMode.current == UiMode.Miuix) {
        DetailPageHost(
            title = stringResource(R.string.licenses_screen_title),
            subtitle = stringResource(R.string.licenses_screen_subtitle),
            onBack = onBack,
        ) { contentPadding, pageModifier ->
            if (libraries == null) {
                Column(
                    modifier = pageModifier
                        .fillMaxSize()
                        .padding(contentPadding)
                        .padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    AdaptiveSummaryCard(
                        icon = Icons.Rounded.Verified,
                        title = stringResource(R.string.licenses_inventory_title),
                        summary = stringResource(R.string.licenses_inventory_subtitle),
                        trailingText = "…",
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Box(
                        modifier = Modifier.fillMaxWidth().weight(1f),
                        contentAlignment = Alignment.Center,
                    ) {
                        AdaptiveCircularProgressIndicator()
                    }
                }
            } else {
                // Keep the whole detail page on one native MIUIX scroll chain so the top bar,
                // elastic edge feedback and scroll-end haptics all observe the same deltas.
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .adaptiveVerticalScrollFeedback()
                        .then(pageModifier),
                    overscrollEffect = null,
                    contentPadding = PaddingValues(
                        start = 12.dp,
                        top = contentPadding.calculateTopPadding() + 12.dp,
                        end = 12.dp,
                        bottom = contentPadding.calculateBottomPadding() + 20.dp,
                    ),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    item(key = "inventory") {
                        AdaptiveSummaryCard(
                            icon = Icons.Rounded.Verified,
                            title = stringResource(R.string.licenses_inventory_title),
                            summary = stringResource(R.string.licenses_inventory_subtitle),
                            trailingText = libraryCount.toString(),
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    items(count = miuixLibraries.size, key = { miuixLibraries[it].uniqueId }) { index ->
                        val library = miuixLibraries[index]
                        LicenseLibraryRow(
                            library = library,
                            onClick = { selectedLibrary = library },
                        )
                    }
                }
            }
        }
        retainedLibrary.value?.let { library ->
            LicenseDetailsDialog(
                show = selectedLibrary != null,
                library = library,
                onDismiss = { selectedLibrary = null },
                onDismissFinished = retainedLibrary.onDismissFinished,
            )
        }
        return
    }

    // Use the native M3E large collapsing bar while keeping DuckNavHost as the sole route owner;
    // DetailPageHost only provides the visual chrome.
    Box(modifier = modifier.fillMaxSize()) {
        DetailPageHost(
            title = stringResource(R.string.licenses_screen_title),
            subtitle = stringResource(R.string.licenses_screen_subtitle),
            onBack = onBack,
        ) { contentPadding, pageModifier ->
            Column(
                modifier = pageModifier
                    .fillMaxSize()
                    .padding(contentPadding)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                AdaptiveSummaryCard(
                    icon = Icons.Rounded.Verified,
                    title = stringResource(R.string.licenses_inventory_title),
                    summary = stringResource(R.string.licenses_inventory_subtitle),
                    trailingText = libraryCount?.toString() ?: "…",
                    modifier = Modifier.fillMaxWidth(),
                )

                LibrariesContainer(
                    libraries = libraries,
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    contentPadding = PaddingValues(vertical = 2.dp),
                    colors = LibraryDefaults.libraryColors(
                        libraryBackgroundColor = MaterialTheme.colorScheme.surfaceContainer,
                        libraryContentColor = MaterialTheme.colorScheme.onSurface,
                        licenseChipColors = LibraryDefaults.chipColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer,
                            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                        ),
                    ),
                    onLibraryClick = { library ->
                        selectedLibrary = library
                        true
                    },
                    libraryRow = { _, library, _, toggle, _ ->
                        LicenseLibraryRow(library = library, onClick = toggle)
                    },
                )
            }
        }
    }

    selectedLibrary?.let { library ->
        LicenseDetailsDialog(show = true, library = library, onDismiss = { selectedLibrary = null })
    }
}
