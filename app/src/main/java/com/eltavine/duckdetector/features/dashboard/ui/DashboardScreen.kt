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

import android.content.ContentValues
import android.content.Context
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.Insights
import androidx.compose.material.icons.rounded.ReportProblem
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Smartphone
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.ViewCompositionStrategy
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.core.ui.components.DetectorAutoExpansionDirective
import com.eltavine.duckdetector.core.ui.components.LocalDetectorAutoExpansionDirective
import com.eltavine.duckdetector.core.ui.components.MetricChip
import com.eltavine.duckdetector.core.ui.components.StatusBadge
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.components.embedDigitalWatermark
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.core.ui.model.MetricChipModel
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.features.bootloader.ui.card.BootloaderDetectorCard
import com.eltavine.duckdetector.features.customrom.ui.card.CustomRomDetectorCard
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorCardEntry
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardUiState
import com.eltavine.duckdetector.features.deviceinfo.ui.card.DeviceInfoCard
import com.eltavine.duckdetector.features.deviceinfo.ui.model.DeviceInfoCardModel
import com.eltavine.duckdetector.features.dangerousapps.ui.card.DangerousAppsDetectorCard
import com.eltavine.duckdetector.features.kernelcheck.ui.card.KernelCheckDetectorCard
import com.eltavine.duckdetector.features.lsposed.ui.card.LSPosedDetectorCard
import com.eltavine.duckdetector.features.memory.ui.card.MemoryDetectorCard
import com.eltavine.duckdetector.features.mount.ui.card.MountDetectorCard
import com.eltavine.duckdetector.features.nativeroot.ui.card.NativeRootDetectorCard
import com.eltavine.duckdetector.features.playintegrityfix.ui.card.PlayIntegrityFixDetectorCard
import com.eltavine.duckdetector.features.selinux.ui.card.SelinuxDetectorCard
import com.eltavine.duckdetector.features.su.ui.card.SuDetectorCard
import com.eltavine.duckdetector.features.systemproperties.ui.card.SystemPropertiesDetectorCard
import com.eltavine.duckdetector.features.tee.ui.card.TeeDetectorCard
import com.eltavine.duckdetector.features.tee.ui.model.TeeFooterActionId
import com.eltavine.duckdetector.features.virtualization.ui.card.VirtualizationDetectorCard
import com.eltavine.duckdetector.features.zygisk.ui.card.ZygiskDetectorCard
import com.eltavine.duckdetector.ui.theme.DuckDetectorTheme
import com.eltavine.duckdetector.ui.theme.ShapeTokens
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

private const val EXPORT_JPEG_QUALITY = 90
private const val MIN_EXPORT_JPEG_QUALITY = 55
private const val MAX_EXPORT_BITMAP_HEIGHT = 16_384
// ~100 MB in ARGB_8888 pixels; well under most devices' per-app memory ceiling.
private const val MAX_EXPORT_BITMAP_BYTES = 100 * 1024 * 1024L
private const val MAX_EXPORT_FILE_BYTES = 2_097_152 // 2 MiB
private val EXPORT_RELATIVE_DIR = "${Environment.DIRECTORY_PICTURES}/DuckDetector"

@Composable
fun DashboardScreen(
    uiState: DashboardUiState,
    showTeeDetailsDialog: Boolean,
    showTeeCertificatesDialog: Boolean,
    onTeeExpandedChange: (Boolean) -> Unit,
    onTeeFooterAction: (TeeFooterActionId) -> Unit,
    onDismissTeeDetails: () -> Unit,
    onDismissTeeCertificates: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val view = LocalView.current
    val scope = rememberCoroutineScope()
    val darkTheme = isSystemInDarkTheme()
    var exporting by rememberSaveable { mutableStateOf(false) }

    DashboardScreenContent(
        uiState = uiState,
        showTeeDetailsDialog = showTeeDetailsDialog,
        showTeeCertificatesDialog = showTeeCertificatesDialog,
        onTeeExpandedChange = onTeeExpandedChange,
        onTeeFooterAction = onTeeFooterAction,
        onDismissTeeDetails = onDismissTeeDetails,
        onDismissTeeCertificates = onDismissTeeCertificates,
        modifier = modifier.fillMaxSize(),
        scrollable = true,
        includeSystemBarsPadding = true,
        showExportButton = true,
        exporting = exporting,
        onExportClick = {
            if (!exporting) {
                scope.launch {
                    exporting = true
                    val result = runCatching {
                        exportDashboardLongScreenshot(
                            context = context,
                            anchorView = view,
                            uiState = uiState,
                            darkTheme = darkTheme,
                        )
                    }
                    exporting = false
                    result.onSuccess {
                        Toast.makeText(
                            context,
                            "Long screenshot saved to Pictures/DuckDetector",
                            Toast.LENGTH_SHORT,
                        ).show()
                    }.onFailure { throwable ->
                        val message = throwable.message ?: "unknown error"
                        Toast.makeText(
                            context,
                            "Export failed: $message",
                            Toast.LENGTH_LONG,
                        ).show()
                    }
                }
            }
        },
    )
}

@Composable
private fun DashboardScreenContent(
    uiState: DashboardUiState,
    showTeeDetailsDialog: Boolean,
    showTeeCertificatesDialog: Boolean,
    onTeeExpandedChange: (Boolean) -> Unit,
    onTeeFooterAction: (TeeFooterActionId) -> Unit,
    onDismissTeeDetails: () -> Unit,
    onDismissTeeCertificates: () -> Unit,
    modifier: Modifier = Modifier,
    scrollable: Boolean,
    includeSystemBarsPadding: Boolean,
    showExportButton: Boolean,
    exporting: Boolean,
    onExportClick: () -> Unit,
) {
    val scrollState = rememberScrollState()

    Box(
        modifier = modifier
            .background(MaterialTheme.colorScheme.background)
    ) {
        val contentModifier = Modifier
            .align(Alignment.TopCenter)
            .widthIn(max = 720.dp)
            .fillMaxWidth()
            .then(
                if (includeSystemBarsPadding) {
                    Modifier
                        .statusBarsPadding()
                        .navigationBarsPadding()
                } else {
                    Modifier
                },
            )
            .padding(horizontal = 20.dp, vertical = 20.dp)
            .then(
                if (scrollable) {
                    Modifier.verticalScroll(scrollState)
                } else {
                    Modifier
                },
            )

        Column(
            modifier = contentModifier,
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            DashboardHeaderCard(
                isLoading = uiState.isLoading,
                showExportButton = showExportButton,
                exporting = exporting,
                onExportClick = onExportClick,
            )
            DashboardOverviewCard(uiState = uiState)
            DashboardTopFindingsCard(uiState = uiState)
            DashboardDetectorCardsCard(
                uiState = uiState,
                showTeeDetailsDialog = showTeeDetailsDialog,
                showTeeCertificatesDialog = showTeeCertificatesDialog,
                onTeeExpandedChange = onTeeExpandedChange,
                onTeeFooterAction = onTeeFooterAction,
                onDismissTeeDetails = onDismissTeeDetails,
                onDismissTeeCertificates = onDismissTeeCertificates,
            )
            DashboardDeviceInfoCard(uiState.deviceInfoCard)
            if (scrollable) {
                Spacer(modifier = Modifier.height(96.dp))
            }
        }
    }
}

@Composable
private fun DashboardHeaderCard(
    isLoading: Boolean,
    showExportButton: Boolean,
    exporting: Boolean,
    onExportClick: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Surface(
                shape = ShapeTokens.CornerExtraLargeIncreased,
                color = MaterialTheme.colorScheme.surfaceContainerHighest,
            ) {
                Box(
                    modifier = Modifier
                        .size(82.dp)
                        .padding(18.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_duck_logo),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            WrapSafeText(
                text = stringResource(R.string.app_name),
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.displaySmall,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Rounded.Badge,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(14.dp),
                )
                Spacer(modifier = Modifier.size(6.dp))
                WrapSafeText(
                    text = "${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Schedule,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(14.dp),
                    )
                    Spacer(modifier = Modifier.size(6.dp))
                    WrapSafeText(
                        text = "Build Time (UTC)",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                WrapSafeText(
                    text = formatBuildTimeUtc(BuildConfig.BUILD_TIME_UTC),
                    modifier = Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }

            val uriHandler = LocalUriHandler.current

            Surface(
                shape = ShapeTokens.CornerFull,
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
            ) {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clickable { uriHandler.openUri("https://t.me/duck_detector") }
                        .padding(10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        painter = painterResource(R.drawable.ic_telegram),
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            WrapSafeText(
                text = "Detection results",
                style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = if (isLoading) {
                    "Detector cards are still collecting local evidence. Export captures the current state as a long screenshot."
                } else {
                    "Export the current dashboard as a long screenshot with an embedded device watermark."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (showExportButton) {
                FilledTonalButton(
                    onClick = onExportClick,
                    enabled = !exporting,
                ) {
                    if (exporting) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Icon(
                            imageVector = Icons.Rounded.FileDownload,
                            contentDescription = null,
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    WrapSafeText(
                        text = if (exporting) "Exporting long screenshot..." else "Export long screenshot",
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DashboardOverviewCard(
    uiState: DashboardUiState,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Surface(
                    shape = ShapeTokens.CornerLarge,
                    color = MaterialTheme.colorScheme.surfaceContainerHigh,
                ) {
                    Box(
                        modifier = Modifier
                            .size(48.dp)
                            .padding(12.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Insights,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
                StatusBadge(status = uiState.overview.status)
            }

            WrapSafeText(
                text = uiState.overview.title,
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = uiState.overview.headline,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = uiState.overview.summary,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                uiState.overview.metrics.forEach { metric ->
                    MetricChip(
                        chip = MetricChipModel(
                            label = metric.label,
                            value = metric.value,
                            status = metric.status,
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun DashboardTopFindingsCard(
    uiState: DashboardUiState,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Icon(
                imageVector = Icons.Rounded.ReportProblem,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
            WrapSafeText(
                text = "Top findings",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )

            uiState.topFindings.forEachIndexed { index, finding ->
                if (index > 0) {
                    HorizontalDivider(
                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.32f),
                    )
                }
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    StatusBadge(status = finding.status)
                    WrapSafeText(
                        text = finding.detectorTitle,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = finding.headline,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = finding.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun DashboardDetectorCardsCard(
    uiState: DashboardUiState,
    showTeeDetailsDialog: Boolean,
    showTeeCertificatesDialog: Boolean,
    onTeeExpandedChange: (Boolean) -> Unit,
    onTeeFooterAction: (TeeFooterActionId) -> Unit,
    onDismissTeeDetails: () -> Unit,
    onDismissTeeCertificates: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = ShapeTokens.CornerExtraLargeIncreased,
            color = MaterialTheme.colorScheme.surfaceContainerLow,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                WrapSafeText(
                    text = "Detector cards",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = "The long screenshot export automatically expands detector cards so the image keeps the detailed evidence, not only the collapsed overview.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        uiState.detectorCards.forEach { entry ->
            DashboardDetectorCard(
                entry = entry,
                showTeeDetailsDialog = showTeeDetailsDialog,
                showTeeCertificatesDialog = showTeeCertificatesDialog,
                onTeeExpandedChange = onTeeExpandedChange,
                onTeeFooterAction = onTeeFooterAction,
                onDismissTeeDetails = onDismissTeeDetails,
                onDismissTeeCertificates = onDismissTeeCertificates,
            )
        }
    }
}

@Composable
private fun DashboardDeviceInfoCard(
    deviceInfoCard: DeviceInfoCardModel,
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = ShapeTokens.CornerExtraLargeIncreased,
            color = MaterialTheme.colorScheme.surfaceContainerLow,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Icon(
                    imageVector = Icons.Rounded.Smartphone,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
                WrapSafeText(
                    text = "Device information",
                    style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                WrapSafeText(
                    text = "The export embeds a device watermark derived from this section into the output image.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        DeviceInfoCard(model = deviceInfoCard)
    }
}

private fun detectorCardTitle(entry: DashboardDetectorCardEntry): String = when (entry) {
    is DashboardDetectorCardEntry.Bootloader -> entry.model.title
    is DashboardDetectorCardEntry.CustomRom -> entry.model.title
    is DashboardDetectorCardEntry.DangerousApps -> entry.model.title
    is DashboardDetectorCardEntry.KernelCheck -> entry.model.title
    is DashboardDetectorCardEntry.LSPosed -> entry.model.title
    is DashboardDetectorCardEntry.Memory -> entry.model.title
    is DashboardDetectorCardEntry.Mount -> entry.model.title
    is DashboardDetectorCardEntry.NativeRoot -> entry.model.title
    is DashboardDetectorCardEntry.PlayIntegrityFix -> entry.model.title
    is DashboardDetectorCardEntry.Selinux -> entry.model.title
    is DashboardDetectorCardEntry.Su -> entry.model.title
    is DashboardDetectorCardEntry.SystemProperties -> entry.model.title
    is DashboardDetectorCardEntry.Tee -> entry.model.title
    is DashboardDetectorCardEntry.Virtualization -> entry.model.title
    is DashboardDetectorCardEntry.Zygisk -> entry.model.title
}

@Composable
private fun DashboardDetectorCard(
    entry: DashboardDetectorCardEntry,
    showTeeDetailsDialog: Boolean,
    showTeeCertificatesDialog: Boolean,
    onTeeExpandedChange: (Boolean) -> Unit,
    onTeeFooterAction: (TeeFooterActionId) -> Unit,
    onDismissTeeDetails: () -> Unit,
    onDismissTeeCertificates: () -> Unit,
) {
    when (entry) {
        is DashboardDetectorCardEntry.Bootloader -> BootloaderDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.CustomRom -> CustomRomDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.DangerousApps -> DangerousAppsDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.KernelCheck -> KernelCheckDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.LSPosed -> LSPosedDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.Memory -> MemoryDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.Mount -> MountDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.NativeRoot -> NativeRootDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.PlayIntegrityFix -> PlayIntegrityFixDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.Selinux -> SelinuxDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.Su -> SuDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.SystemProperties -> {
            SystemPropertiesDetectorCard(model = entry.model)
        }

        is DashboardDetectorCardEntry.Tee -> {
            TeeDetectorCard(
                model = entry.model,
                showDetailsDialog = showTeeDetailsDialog,
                showCertificatesDialog = showTeeCertificatesDialog,
                onExpandedChange = onTeeExpandedChange,
                onFooterAction = onTeeFooterAction,
                onDismissDetails = onDismissTeeDetails,
                onDismissCertificates = onDismissTeeCertificates,
            )
        }

        is DashboardDetectorCardEntry.Virtualization -> VirtualizationDetectorCard(model = entry.model)
        is DashboardDetectorCardEntry.Zygisk -> ZygiskDetectorCard(model = entry.model)
    }
}

private suspend fun exportDashboardLongScreenshot(
    context: Context,
    anchorView: View,
    uiState: DashboardUiState,
    darkTheme: Boolean,
): Uri {
    return withContext(Dispatchers.Main) {
        val host = anchorView.rootView as? ViewGroup
            ?: error("Unable to access root view for export")

        // Render at 1x density so all dp-based sizes collapse to the minimum pixel
        // count. This drastically reduces the bitmap footprint (the full-height
        // content is typically 70k+ px at 3x, but ~23k px at 1x), allowing a single
        // JPEG encode to succeed while keeping every detail sharp enough for sharing.
        val exportDensity = 1f
        val exportContext = context.createConfigurationContext(
            Configuration(context.resources.configuration).apply {
                densityDpi = (exportDensity * 160).toInt()
            },
        )
        val displayMetrics = exportContext.resources.displayMetrics
        val screenWidth = displayMetrics.widthPixels.coerceAtLeast(1)
        val contentMaxWidthPx = (720.dp.value * exportDensity).roundToInt()
        val width = minOf(screenWidth, contentMaxWidthPx).coerceAtLeast(1)

        // Only auto-expand cards that actually carry a problem (DANGER/WARNING).
        // Clean cards (INFO/ALL_CLEAR) stay collapsed so the long screenshot keeps
        // a manageable height while still surfacing every detector's verdict.
        val expandedTitles: Set<String> = uiState.detectorCards
            .filter { entry ->
                val severity = entry.status.severity
                severity == DetectionSeverity.DANGER ||
                    severity == DetectionSeverity.WARNING
            }
            .mapTo(mutableSetOf()) { entry -> detectorCardTitle(entry) }

        val container = FrameLayout(exportContext).apply {
            alpha = 0f
            layoutParams = ViewGroup.LayoutParams(
                width,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
        }
        val composeView = ComposeView(exportContext).apply {
            layoutParams = FrameLayout.LayoutParams(
                width,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            )
            setViewCompositionStrategy(ViewCompositionStrategy.DisposeOnDetachedFromWindow)
            setContent {
                DuckDetectorTheme(
                    darkTheme = darkTheme,
                    dynamicColor = false,
                ) {
                    CompositionLocalProvider(
                        LocalDetectorAutoExpansionDirective provides DetectorAutoExpansionDirective(
                            titles = expandedTitles,
                            disableAnimation = true,
                        ),
                    ) {
                        DashboardScreenContent(
                            uiState = uiState,
                            showTeeDetailsDialog = false,
                            showTeeCertificatesDialog = false,
                            onTeeExpandedChange = {},
                            onTeeFooterAction = {},
                            onDismissTeeDetails = {},
                            onDismissTeeCertificates = {},
                            modifier = Modifier
                                .fillMaxWidth()
                                .wrapContentHeight(),
                            scrollable = false,
                            includeSystemBarsPadding = false,
                            showExportButton = false,
                            exporting = false,
                            onExportClick = {},
                        )
                    }
                }
            }
        }

        container.addView(composeView)
        host.addView(container)
        val rawBitmap = try {
            delay(80L)
            val widthSpec = View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY)
            val heightSpec = View.MeasureSpec.makeMeasureSpec(0, View.MeasureSpec.UNSPECIFIED)
            composeView.measure(widthSpec, heightSpec)
            val measuredHeight = composeView.measuredHeight.coerceAtLeast(1)
            composeView.layout(0, 0, width, measuredHeight)
            renderViewToBitmap(
                view = composeView,
                width = width,
                height = measuredHeight,
            )
        } finally {
            host.removeView(container)
        }

        // Post-render safety clamp: even at 1x, an extreme device (hundreds of
        // flagged apps) can still produce a bitmap too large for the JPEG encoder.
        // Scale down the long axis so both dimensions fit within hardware limits.
        val bitmap = if (rawBitmap.height > MAX_EXPORT_BITMAP_HEIGHT ||
            rawBitmap.byteCount > MAX_EXPORT_BITMAP_BYTES
        ) {
            val scale = minOf(
                MAX_EXPORT_BITMAP_HEIGHT.toFloat() / rawBitmap.height,
                (MAX_EXPORT_BITMAP_BYTES.toFloat() / rawBitmap.byteCount).coerceAtMost(1f),
            )
            val scaledWidth = (rawBitmap.width * scale).roundToInt().coerceAtLeast(1)
            val scaledHeight = (rawBitmap.height * scale).roundToInt().coerceAtLeast(1)
            Log.d(
                "DuckExport",
                "scaling bitmap ${rawBitmap.width}x${rawBitmap.height} -> " +
                    "${scaledWidth}x${scaledHeight} (scale=${"%.2f".format(scale)})",
            )
            Bitmap.createScaledBitmap(rawBitmap, scaledWidth, scaledHeight, true)
                .also { rawBitmap.recycle() }
        } else {
            rawBitmap
        }
        embedDigitalWatermark(
            bitmap = bitmap,
            deviceInfoCard = uiState.deviceInfoCard,
        )

        val uri = saveBitmapToGallery(
            context = context,
            bitmap = bitmap,
        )
        bitmap.recycle()
        uri
    }
}

private fun renderViewToBitmap(
    view: View,
    width: Int,
    height: Int,
): Bitmap {
    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bitmap)
    view.draw(canvas)
    Log.d(
        "DuckExport",
        "rendered bitmap: ${bitmap.width}x${bitmap.height}, " +
            "byteCount=${bitmap.byteCount}, " +
            "allocationByteCount=${bitmap.allocationByteCount}, " +
            "config=${bitmap.config}",
    )
    return bitmap
}

private suspend fun saveBitmapToGallery(
    context: Context,
    bitmap: Bitmap,
): Uri = withContext(Dispatchers.IO) {
    val fileName = "duckdetector-scan-${
        SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
    }.jpg"
    val resolver = context.contentResolver
    val values = ContentValues().apply {
        put(MediaStore.Images.Media.DISPLAY_NAME, fileName)
        put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
        put(MediaStore.Images.Media.RELATIVE_PATH, EXPORT_RELATIVE_DIR)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            put(MediaStore.Images.Media.IS_PENDING, 1)
        }
    }

    val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
        ?: error("Failed to create MediaStore record")

    try {
        val encodedBytes = encodeBitmapForExport(bitmap)
        resolver.openOutputStream(uri)?.use { output ->
            Log.d(
                "DuckExport",
                "write JPEG bytes=${encodedBytes.size}, " +
                    "src=${bitmap.width}x${bitmap.height} (${bitmap.byteCount}B), " +
                    "isRecycled=${bitmap.isRecycled}",
            )
            output.write(encodedBytes)
            output.flush()
        } ?: error("Failed to open output stream")

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val publishValues = ContentValues().apply {
                put(MediaStore.Images.Media.IS_PENDING, 0)
            }
            resolver.update(uri, publishValues, null, null)
        }
        uri
    } catch (throwable: Throwable) {
        resolver.delete(uri, null, null)
        throw throwable
    }
}

private fun encodeBitmapForExport(bitmap: Bitmap): ByteArray {
    var workingBitmap = bitmap

    while (true) {
        val encoded = compressBitmapToTargetSize(workingBitmap)
        if (encoded != null) {
            if (workingBitmap !== bitmap) {
                workingBitmap.recycle()
            }
            return encoded
        }

        val nextWidth = (workingBitmap.width * 0.9f).roundToInt().coerceAtLeast(1)
        val nextHeight = (workingBitmap.height * 0.9f).roundToInt().coerceAtLeast(1)
        if (nextWidth == workingBitmap.width && nextHeight == workingBitmap.height) {
            break
        }

        val scaledBitmap = Bitmap.createScaledBitmap(workingBitmap, nextWidth, nextHeight, true)
        Log.d(
            "DuckExport",
            "retry export with scaled bitmap ${workingBitmap.width}x${workingBitmap.height} -> " +
                "${scaledBitmap.width}x${scaledBitmap.height}",
        )
        if (workingBitmap !== bitmap) {
            workingBitmap.recycle()
        }
        workingBitmap = scaledBitmap
    }

    if (workingBitmap !== bitmap) {
        workingBitmap.recycle()
    }
    error("Unable to compress export below ${MAX_EXPORT_FILE_BYTES / 1024} KiB")
}

private fun compressBitmapToTargetSize(bitmap: Bitmap): ByteArray? {
    val stream = ByteArrayOutputStream()

    for (quality in EXPORT_JPEG_QUALITY downTo MIN_EXPORT_JPEG_QUALITY step 5) {
        stream.reset()
        val compressed = bitmap.compress(Bitmap.CompressFormat.JPEG, quality, stream)
        if (!compressed) {
            error("JPEG compression failed")
        }

        val encodedBytes = stream.toByteArray()
        Log.d(
            "DuckExport",
            "try JPEG q$quality => ${encodedBytes.size} bytes for ${bitmap.width}x${bitmap.height}",
        )
        if (encodedBytes.size <= MAX_EXPORT_FILE_BYTES) {
            return encodedBytes
        }
    }

    return null
}
