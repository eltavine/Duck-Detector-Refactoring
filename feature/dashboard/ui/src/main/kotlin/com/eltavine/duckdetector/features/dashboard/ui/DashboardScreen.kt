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

package com.eltavine.duckdetector.features.dashboard.ui

import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberOverscrollEffect
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.designsystem.components.StatusBarProtection
import com.eltavine.duckdetector.core.designsystem.theme.DuckTheme
import com.eltavine.duckdetector.core.designsystem.components.DuckPanel
import com.eltavine.duckdetector.core.designsystem.theme.DuckTypography
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.ui.components.LocalDetectorCardExpansionSignal
import com.eltavine.duckdetector.core.ui.detector.DetectorSession
import com.eltavine.duckdetector.core.ui.detector.DeviceProfileSession
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.dashboard.presentation.export.DashboardExport
import com.eltavine.duckdetector.features.dashboard.presentation.export.DashboardReportRenderer
import com.eltavine.duckdetector.features.dashboard.presentation.export.ExportHeader
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardFindingModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.presentation.model.DashboardUiState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveCircularProgressIndicator
import io.github.xiaotong6666.uihelper.adaptive.AdaptiveContent
import io.github.xiaotong6666.uihelper.adaptive.adaptiveContainerContentColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveScrollableOverscrollEffect
import io.github.xiaotong6666.uihelper.adaptive.adaptiveSecondaryTextColor
import io.github.xiaotong6666.uihelper.adaptive.adaptiveValue
import io.github.xiaotong6666.uihelper.adaptive.adaptiveVerticalScrollFeedback
import io.github.xiaotong6666.uihelper.adaptive.adaptiveViewportOverscroll
import kotlinx.coroutines.launch

@Composable
fun DashboardScreen(
    uiState: DashboardUiState,
    detectors: List<DetectorSession>,
    deviceProfile: DeviceProfileSession,
    modifier: Modifier = Modifier,
    scaffoldPadding: PaddingValues? = null,
    pageModifier: Modifier = Modifier,
) {
    val materialOverscrollEffect = rememberOverscrollEffect()
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()
    var expansionRequest by remember { mutableStateOf<DashboardExpansionRequest?>(null) }
    val hostedHorizontalInset = adaptiveValue(material = 16.dp, miuix = 12.dp)
    val pageSpacing = adaptiveValue(material = 16.dp, miuix = 12.dp)
    val showStandaloneMaterialChrome = adaptiveValue(
        material = scaffoldPadding == null,
        miuix = false,
    )
    val layoutDirection = LocalLayoutDirection.current
    val context = LocalContext.current
    val resources = LocalResources.current
    val buildInfo = LocalAppBuildInfo.current
    val orderedDetectors = remember(uiState.cardOrder, detectors) {
        val detectorsById = detectors.associateBy { it.id }
        uiState.cardOrder.mapNotNull { detectorsById[it] }
    }
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri != null) {
            try {
                val text = DashboardReportRenderer.render(
                    DashboardExport(
                        header = ExportHeader(
                            versionName = buildInfo.versionName,
                            versionCode = buildInfo.versionCode,
                            buildHash = buildInfo.buildHash,
                            buildTime = formatBuildTimeUtc(buildInfo.buildTimeUtc),
                            reportTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss (z)", Locale.US).format(Date()),
                        ),
                        overview = uiState.overview,
                        topFindings = uiState.topFindings,
                        detectors = orderedDetectors.map { it.report() },
                        device = deviceProfile.report(),
                    ),
                )
                context.contentResolver.openOutputStream(uri)?.use { stream ->
                    stream.write(text.toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(
                    context,
                    resources.getString(R.string.dashboard_report_saved),
                    Toast.LENGTH_SHORT,
                ).show()
            } catch (e: Exception) {
                Toast.makeText(
                    context,
                    e.message
                        ?.takeIf(String::isNotBlank)
                        ?.let { message ->
                            resources.getString(R.string.dashboard_report_save_failed, message)
                        }
                        ?: resources.getString(R.string.dashboard_report_save_failed_unknown),
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(DuckTheme.palette.groupedBackground)
            // Render at the entire page viewport, not at an inset card or scroll item.
            // The LazyColumn below supplies the scroll deltas to the same native effect.
            .adaptiveViewportOverscroll(materialOverscrollEffect),
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                // uihelper preserves the native MIUIX ordering: elastic overscroll remains outside
                // the top-bar nested-scroll observer so its rebound cannot collapse chrome.
                .adaptiveVerticalScrollFeedback()
                .then(pageModifier),
            overscrollEffect = adaptiveScrollableOverscrollEffect(materialOverscrollEffect),
            verticalArrangement = Arrangement.spacedBy(pageSpacing),
            contentPadding = if (scaffoldPadding != null) {
                // MIUIX owns the top bar and navigation bar. Their insets must not be re-applied.
                PaddingValues(
                    start = scaffoldPadding.calculateStartPadding(layoutDirection) + hostedHorizontalInset,
                    top = scaffoldPadding.calculateTopPadding() + 12.dp,
                    end = scaffoldPadding.calculateEndPadding(layoutDirection) + hostedHorizontalInset,
                    bottom = scaffoldPadding.calculateBottomPadding() + 16.dp,
                )
            } else {
                WindowInsets.safeDrawing
                    .add(WindowInsets(left = 16.dp, top = 12.dp, right = 16.dp, bottom = 96.dp))
                    .asPaddingValues()
            },
        ) {
            // Hosted pages put brand actions in the real app bar. Keep the original
            // inline brand header only for standalone/dashboard preview hosts.
            if (showStandaloneMaterialChrome) {
                item { BrandHeader() }
            }
            item {
                DashboardSummarySection(
                    overview = uiState.overview,
                    findings = uiState.topFindings,
                    showLoadingOverlay = uiState.isLoading,
                    onExportReport = { exportLauncher.launch(generateExportReportFileName()) },
                    onFindingClick = { finding ->
                        val detectorId = finding.detectorId ?: return@DashboardSummarySection
                        val detectorIndex = orderedDetectors.indexOfFirst { it.id == detectorId }
                        if (detectorIndex >= 0) {
                            val detectorStartIndex = if (showStandaloneMaterialChrome) 2 else 1
                            coroutineScope.launch {
                                listState.animateScrollToItem(detectorStartIndex + detectorIndex)
                                expansionRequest = DashboardExpansionRequest(
                                    detectorId = detectorId,
                                    signal = (expansionRequest?.signal ?: 0L) + 1L,
                                )
                            }
                        }
                    },
                )
            }
            items(
                items = orderedDetectors,
                key = { detector -> detector.id.value },
            ) { detector ->
                val expansionSignal = expansionRequest
                    ?.takeIf { request -> request.detectorId == detector.id }
                    ?.signal
                    ?: 0L
                CompositionLocalProvider(
                    LocalDetectorCardExpansionSignal provides expansionSignal,
                ) {
                    detector.Card()
                }
            }
            item {
                deviceProfile.Card()
            }
        }

        if (showStandaloneMaterialChrome) {
            StatusBarProtection(modifier = Modifier.align(Alignment.TopCenter))
        }
    }
}

private data class DashboardExpansionRequest(
    val detectorId: DetectorId,
    val signal: Long,
)

@Composable
private fun DashboardSummarySection(
    overview: DashboardOverviewModel,
    findings: List<DashboardFindingModel>,
    showLoadingOverlay: Boolean,
    onExportReport: () -> Unit,
    onFindingClick: (DashboardFindingModel) -> Unit,
) {
    if (showLoadingOverlay) {
        // Do not draw the finished Danger card behind an opaque loading overlay. Its independent
        // Material radius leaked through the MIUIX squircle corners, and made the placeholder
        // inherit the combined height of cards that are not ready yet.
        DashboardLoadingOverlay()
    } else {
        // The status hero and finding queue already have their own internal spacing.
        // An additional 24dp here produced the empty band between the two cards.
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            DashboardOverviewCard(model = overview, onExportReport = onExportReport)
            DashboardFindingsCard(
                findings = findings,
                onFindingClick = onFindingClick,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun DashboardLoadingOverlay(
    modifier: Modifier = Modifier,
) {
    DuckPanel(
        modifier = modifier,
        contentPadding = PaddingValues(start = 28.dp, end = 28.dp, top = 44.dp, bottom = 44.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            AdaptiveContent(
                miuix = {
                    // Native MIUIX indeterminate progress: grey track and moving accent arc.
                    AdaptiveCircularProgressIndicator(size = 48.dp)
                },
                material = { LoadingIndicator(modifier = Modifier.size(56.dp)) },
            )
            WrapSafeText(
                text = stringResource(R.string.dashboard_loading_title),
                modifier = Modifier.padding(top = 6.dp),
                style = DuckTypography.LoadingTitle,
                color = adaptiveContainerContentColor(),
                textAlign = TextAlign.Center,
            )
            WrapSafeText(
                text = stringResource(R.string.dashboard_loading_summary),
                style = DuckTypography.LoadingSupporting,
                color = adaptiveSecondaryTextColor(),
                textAlign = TextAlign.Center,
            )
        }
    }
}

internal fun generateExportReportFileName(
    model: String = Build.MODEL,
    nowEpochMillis: Long = System.currentTimeMillis(),
): String {
    val sanitizedModel = model.trim().ifBlank { "unknown" }
        .replace(Regex("[^a-zA-Z0-9._-]"), "_")
    // Filenames are machine-readable and must not vary with the device language/locale.
    val timestampFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.ROOT).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
    val timestamp = timestampFormat.format(Date(nowEpochMillis))
    return "duck_detector_report_${sanitizedModel}_$timestamp.txt"
}
