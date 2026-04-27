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

import android.content.ClipData
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Timer
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.FileDownload
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.ContainedLoadingIndicator
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import compose.icons.SimpleIcons
import compose.icons.simpleicons.Tencentqq
import com.eltavine.duckdetector.BuildConfig
import com.eltavine.duckdetector.core.ui.model.DetectionSeverity
import com.eltavine.duckdetector.R
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import com.eltavine.duckdetector.core.ui.presentation.formatBuildTimeUtc
import com.eltavine.duckdetector.core.ui.presentation.rememberStatusAppearance
import com.eltavine.duckdetector.features.bootloader.ui.card.BootloaderDetectorCard
import com.eltavine.duckdetector.features.customrom.ui.card.CustomRomDetectorCard
import com.eltavine.duckdetector.features.dangerousapps.ui.card.DangerousAppsDetectorCard
import com.eltavine.duckdetector.features.dashboard.data.DashboardExportFormatter
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorCardEntry
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardFindingModel
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewMetricModel
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardOverviewModel
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardUiState
import com.eltavine.duckdetector.features.deviceinfo.ui.card.DeviceInfoCard
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
import com.eltavine.duckdetector.ui.theme.ShapeTokens

private const val DUCK_DETECTOR_QQ_GROUP = "1079283524"
private const val DUCK_DETECTOR_QQ_GROUP_URL =
    "https://qun.qq.com/universal-share/share?ac=1&authKey=VWdSICnmxMiNF1t409UcE%2FjdQVeorZKvrKP85I2pepXf4rfv9IFfdAw8kAuMdk5v&busi_data=eyJncm91cENvZGUiOiIxMDc5MjgzNTI0IiwidG9rZW4iOiJ2Q3VSSll2QndhK3JoZlhHZFU4VmxUSFREdjBVVHhFNHlTbXVPVDkzY0twTHlJTldSZVFlUmxncjlnM0Rac2dwIiwidWluIjoiMzMzNDcxMzIzMyJ9&data=ms9NmidW7tH7vZrZkYOux0z9cAUWBOp4THmPYdBeCpt6sBVyd1oP9E3lL-0yToQMBBTK3X7aZQ9SLnzxEmxWlQ&svctype=4&tempid=h5_group_info"

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
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        if (uri != null) {
            try {
                val formatter = DashboardExportFormatter()
                val text = formatter.format(uiState)
                context.contentResolver.openOutputStream(uri)?.use { stream ->
                    stream.write(text.toByteArray(Charsets.UTF_8))
                }
                Toast.makeText(
                    context,
                    "Report saved",
                    Toast.LENGTH_SHORT,
                ).show()
            } catch (e: Exception) {
                Toast.makeText(
                    context,
                    "Save failed: ${e.message}",
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(18.dp),
            contentPadding = PaddingValues(
                start = 20.dp,
                top = 16.dp,
                end = 20.dp,
                bottom = 28.dp,
            ),
        ) {
            item { BrandHeader() }
            item {
                ExportButton(
                    onClick = {
                        exportLauncher.launch("duck_detector_report.txt")
                    },
                )
            }
            item {
                DashboardSummarySection(
                    overview = uiState.overview,
                    findings = uiState.topFindings,
                    showLoadingOverlay = uiState.isLoading,
                )
            }
            items(
                items = uiState.detectorCards,
                key = { entry -> entry.id },
            ) { entry ->
                when (entry) {
                    is DashboardDetectorCardEntry.Bootloader -> {
                        BootloaderDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.Mount -> {
                        MountDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.CustomRom -> {
                        CustomRomDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.Selinux -> {
                        SelinuxDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.DangerousApps -> {
                        DangerousAppsDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.KernelCheck -> {
                        KernelCheckDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.Memory -> {
                        MemoryDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.LSPosed -> {
                        LSPosedDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.NativeRoot -> {
                        NativeRootDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.PlayIntegrityFix -> {
                        PlayIntegrityFixDetectorCard(model = entry.model)
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

                    is DashboardDetectorCardEntry.Su -> {
                        SuDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.SystemProperties -> {
                        SystemPropertiesDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.Virtualization -> {
                        VirtualizationDetectorCard(model = entry.model)
                    }

                    is DashboardDetectorCardEntry.Zygisk -> {
                        ZygiskDetectorCard(model = entry.model)
                    }
                }
            }
            item {
                DeviceInfoCard(model = uiState.deviceInfoCard)
            }
        }
    }
}

@Composable
private fun DashboardSummarySection(
    overview: DashboardOverviewModel,
    findings: List<DashboardFindingModel>,
    showLoadingOverlay: Boolean,
) {
    Box(modifier = Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
            DashboardOverviewCard(model = overview)
            DashboardFindingsCard(findings = findings)
        }

        if (showLoadingOverlay) {
            DashboardLoadingOverlay(
                modifier = Modifier.matchParentSize(),
            )
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun DashboardLoadingOverlay(
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .background(MaterialTheme.colorScheme.surface),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            ContainedLoadingIndicator(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                indicatorColor = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            WrapSafeText(
                text = "Running local checks",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
            WrapSafeText(
                text = "Dashboard summary will unlock when the detector cards finish collecting evidence.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun BrandHeader() {
    val uriHandler = LocalUriHandler.current
    val context = LocalContext.current
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Surface(
            shape = ShapeTokens.CornerExtraLargeIncreased,
            color = MaterialTheme.colorScheme.surfaceContainerLow,
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
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
                BrandMetaLine(
                    icon = Icons.Rounded.Badge,
                    text = "${BuildConfig.VERSION_NAME}(${BuildConfig.VERSION_CODE})",
                )
                BuildTimeMetaBlock(
                    icon = Icons.Rounded.Schedule,
                    label = "Build Time (UTC)",
                    time = formatBuildTimeUtc(BuildConfig.BUILD_TIME_UTC),
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp, Alignment.CenterHorizontally),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            SocialGlyph(
                iconRes = R.drawable.ic_telegram,
                onClick = {
                    uriHandler.openUri("https://t.me/duck_detector")
                },
            )
            SocialGlyph(
                iconVector = SimpleIcons.Tencentqq,
                onClick = {
                    context.getSystemService(android.content.ClipboardManager::class.java)
                        ?.setPrimaryClip(
                            ClipData.newPlainText(
                                "Duck Detector QQ group",
                                DUCK_DETECTOR_QQ_GROUP,
                            ),
                        )
                    Toast.makeText(
                        context,
                        "QQ group number copied: $DUCK_DETECTOR_QQ_GROUP",
                        Toast.LENGTH_SHORT,
                    ).show()
                    uriHandler.openUri(DUCK_DETECTOR_QQ_GROUP_URL)
                },
            )
        }
    }
}

@Composable
private fun ExportButton(
    onClick: () -> Unit,
) {
    FilledTonalButton(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(
            imageVector = Icons.Rounded.FileDownload,
            contentDescription = null,
            modifier = Modifier.size(18.dp),
        )
        Spacer(modifier = Modifier.size(8.dp))
        WrapSafeText(
            text = "Export Report",
            style = MaterialTheme.typography.labelLarge,
        )
    }
}

@Composable
private fun BrandMetaLine(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    text: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(14.dp),
        )
        Spacer(modifier = Modifier.size(6.dp))
        WrapSafeText(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun BuildTimeMetaBlock(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    time: String,
) {
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
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(14.dp),
            )
            Spacer(modifier = Modifier.size(6.dp))
            WrapSafeText(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        WrapSafeText(
            text = time,
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun SocialGlyph(
    iconRes: Int? = null,
    iconVector: ImageVector? = null,
    onClick: () -> Unit,
) {
    Surface(
        shape = ShapeTokens.CornerFull,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Box(
            modifier = Modifier
                .size(42.dp)
                .clickable(onClick = onClick)
                .padding(10.dp),
            contentAlignment = Alignment.Center,
        ) {
            when {
                iconVector != null -> Icon(
                    imageVector = iconVector,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                iconRes != null -> Icon(
                    painter = painterResource(iconRes),
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
private fun DashboardOverviewCard(
    model: DashboardOverviewModel,
) {
    val appearance = rememberStatusAppearance(model.status)
    Surface(
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 20.dp, vertical = 22.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surfaceContainerHighest),
                    contentAlignment = Alignment.Center,
                ) {
                    Icon(
                        imageVector = appearance.icon,
                        contentDescription = null,
                        tint = appearance.iconTint,
                    )
                }

                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        if (model.showTitleIcon) {
                            Icon(
                                imageVector = Icons.Outlined.Timer,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(14.dp),
                            )
                        }
                        WrapSafeText(
                            text = model.title,
                            modifier = Modifier.weight(1f),
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    WrapSafeText(
                        text = model.headline,
                        modifier = Modifier.fillMaxWidth(),
                        style = MaterialTheme.typography.displaySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    WrapSafeText(
                        text = model.summary,
                        modifier = Modifier.fillMaxWidth(),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            DashboardMetricGrid(metrics = model.metrics)
        }
    }
}

@Composable
private fun DashboardMetricGrid(
    metrics: List<DashboardOverviewMetricModel>,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        metrics.chunked(2).forEach { rowMetrics ->
            Row(
                modifier = Modifier.fillMaxWidth(0.94f),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                rowMetrics.forEach { metric ->
                    DashboardMetricChip(
                        metric = metric,
                        modifier = Modifier.weight(1f),
                    )
                }
                if (rowMetrics.size == 1) {
                    Spacer(modifier = Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun DashboardMetricChip(
    metric: DashboardOverviewMetricModel,
    modifier: Modifier = Modifier,
) {
    val appearance = rememberStatusAppearance(metric.status)
    Surface(
        modifier = modifier,
        shape = ShapeTokens.CornerLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Icon(
                    imageVector = appearance.icon,
                    contentDescription = null,
                    tint = appearance.iconTint,
                    modifier = Modifier.size(14.dp),
                )
                WrapSafeText(
                    text = metric.label,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            WrapSafeText(
                text = metric.value,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
private fun DashboardFindingsCard(
    findings: List<DashboardFindingModel>,
) {
    Surface(
        shape = ShapeTokens.CornerExtraLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 18.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            DashboardFindingsHeader(findings = findings)
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                findings.forEach { finding ->
                    DashboardFindingRow(finding = finding)
                }
            }
        }
    }
}

@Composable
private fun DashboardFindingsHeader(
    findings: List<DashboardFindingModel>,
) {
    val headerStatus = findings.firstOrNull()?.status
        ?: com.eltavine.duckdetector.core.ui.model.DetectorStatus.allClear()
    val appearance = rememberStatusAppearance(headerStatus)
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Surface(
            shape = ShapeTokens.CornerLargeIncreased,
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .padding(10.dp),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = appearance.icon,
                    contentDescription = null,
                    tint = appearance.iconTint,
                )
            }
        }
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            WrapSafeText(
                text = "Top findings",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = "Priority review queue",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Surface(
            shape = ShapeTokens.CornerLarge,
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
        ) {
            WrapSafeText(
                text = findings.size.toString(),
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun DashboardFindingRow(
    finding: DashboardFindingModel,
) {
    val appearance = rememberStatusAppearance(finding.status)
    Surface(
        shape = ShapeTokens.CornerLargeIncreased,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Surface(
                        shape = CircleShape,
                        color = appearance.iconTint.copy(alpha = 0.14f),
                    ) {
                        Box(
                            modifier = Modifier
                                .size(30.dp)
                                .padding(7.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(
                                imageVector = appearance.icon,
                                contentDescription = null,
                                tint = appearance.iconTint,
                                modifier = Modifier.size(16.dp),
                            )
                        }
                    }
                    WrapSafeText(
                        text = finding.detectorTitle,
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Surface(
                    shape = ShapeTokens.CornerLarge,
                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                ) {
                    WrapSafeText(
                        text = findingSeverityLabel(finding),
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = appearance.iconTint,
                    )
                }
            }
            WrapSafeText(
                text = finding.headline,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.42f),
                thickness = 1.dp,
            )
            WrapSafeText(
                text = finding.detail,
                modifier = Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun findingSeverityLabel(
    finding: DashboardFindingModel,
): String {
    return when (finding.status.severity) {
        DetectionSeverity.DANGER -> "High"
        DetectionSeverity.WARNING -> "Warn"
        DetectionSeverity.INFO -> "Check"
        DetectionSeverity.ALL_CLEAR -> "Clear"
    }
}
