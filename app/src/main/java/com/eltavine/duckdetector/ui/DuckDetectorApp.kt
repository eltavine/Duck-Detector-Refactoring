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

package com.eltavine.duckdetector.ui

import android.Manifest
import android.os.Build
import android.os.SystemClock
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.eltavine.duckdetector.BuildConfig
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import com.eltavine.duckdetector.core.notifications.ScanNotificationPermissions
import com.eltavine.duckdetector.core.notifications.ScanProgressNotificationSnapshot
import com.eltavine.duckdetector.core.notifications.ScanProgressNotifier
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationConsentStore
import com.eltavine.duckdetector.core.notifications.preferences.ScanNotificationPrefs
import com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibilityChecker
import com.eltavine.duckdetector.core.packagevisibility.preferences.PackageVisibilityReviewPrefs
import com.eltavine.duckdetector.core.packagevisibility.preferences.PackageVisibilityReviewStore
import com.eltavine.duckdetector.core.startup.legal.AgreementAcceptancePrefs
import com.eltavine.duckdetector.core.startup.legal.AgreementAcceptanceStore
import com.eltavine.duckdetector.core.startup.legal.AgreementScreen
import com.eltavine.duckdetector.core.ui.components.AlphaBuildBanner
import com.eltavine.duckdetector.core.ui.components.AlphaBuildWarningOverlay
import com.eltavine.duckdetector.core.ui.components.DetectorAutoExpansionDirective
import com.eltavine.duckdetector.core.ui.components.LocalDetectorAutoExpansionDirective
import com.eltavine.duckdetector.core.ui.components.ScreenshotWatermarkOverlay
import com.eltavine.duckdetector.features.bootloader.presentation.BootloaderUiStage
import com.eltavine.duckdetector.features.bootloader.presentation.BootloaderUiState
import com.eltavine.duckdetector.features.bootloader.presentation.BootloaderViewModel
import com.eltavine.duckdetector.features.customrom.presentation.CustomRomUiStage
import com.eltavine.duckdetector.features.customrom.presentation.CustomRomUiState
import com.eltavine.duckdetector.features.customrom.presentation.CustomRomViewModel
import com.eltavine.duckdetector.features.dashboard.ui.DashboardScreen
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorCardEntry
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardDetectorContribution
import com.eltavine.duckdetector.features.dashboard.ui.model.DashboardUiState
import com.eltavine.duckdetector.features.dashboard.ui.model.buildDashboardFindings
import com.eltavine.duckdetector.features.dashboard.ui.model.buildDashboardOverview
import com.eltavine.duckdetector.features.dashboard.ui.model.sortDashboardDetectorCards
import com.eltavine.duckdetector.features.deviceinfo.presentation.DeviceInfoViewModel
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsUiStage
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsUiState
import com.eltavine.duckdetector.features.dangerousapps.presentation.DangerousAppsViewModel
import com.eltavine.duckdetector.features.kernelcheck.presentation.KernelCheckUiStage
import com.eltavine.duckdetector.features.kernelcheck.presentation.KernelCheckUiState
import com.eltavine.duckdetector.features.kernelcheck.presentation.KernelCheckViewModel
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedUiStage
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedUiState
import com.eltavine.duckdetector.features.lsposed.presentation.LSPosedViewModel
import com.eltavine.duckdetector.features.memory.presentation.MemoryUiStage
import com.eltavine.duckdetector.features.memory.presentation.MemoryUiState
import com.eltavine.duckdetector.features.memory.presentation.MemoryViewModel
import com.eltavine.duckdetector.features.mount.presentation.MountUiStage
import com.eltavine.duckdetector.features.mount.presentation.MountUiState
import com.eltavine.duckdetector.features.mount.presentation.MountViewModel
import com.eltavine.duckdetector.features.nativeroot.presentation.NativeRootUiStage
import com.eltavine.duckdetector.features.nativeroot.presentation.NativeRootUiState
import com.eltavine.duckdetector.features.nativeroot.presentation.NativeRootViewModel
import com.eltavine.duckdetector.features.playintegrityfix.presentation.PlayIntegrityFixUiStage
import com.eltavine.duckdetector.features.playintegrityfix.presentation.PlayIntegrityFixUiState
import com.eltavine.duckdetector.features.playintegrityfix.presentation.PlayIntegrityFixViewModel
import com.eltavine.duckdetector.features.selinux.presentation.SelinuxUiStage
import com.eltavine.duckdetector.features.selinux.presentation.SelinuxUiState
import com.eltavine.duckdetector.features.selinux.presentation.SelinuxViewModel
import com.eltavine.duckdetector.features.settings.ui.SettingsScreen
import com.eltavine.duckdetector.features.settings.ui.model.SettingsUiState
import com.eltavine.duckdetector.features.su.presentation.SuUiStage
import com.eltavine.duckdetector.features.su.presentation.SuUiState
import com.eltavine.duckdetector.features.su.presentation.SuViewModel
import com.eltavine.duckdetector.features.systemproperties.presentation.SystemPropertiesUiStage
import com.eltavine.duckdetector.features.systemproperties.presentation.SystemPropertiesUiState
import com.eltavine.duckdetector.features.systemproperties.presentation.SystemPropertiesViewModel
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkConsentStore
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.features.tee.presentation.TeeUiStage
import com.eltavine.duckdetector.features.tee.presentation.TeeUiState
import com.eltavine.duckdetector.features.tee.presentation.TeeViewModel
import com.eltavine.duckdetector.features.virtualization.presentation.VirtualizationUiStage
import com.eltavine.duckdetector.features.virtualization.presentation.VirtualizationUiState
import com.eltavine.duckdetector.features.virtualization.presentation.VirtualizationViewModel
import com.eltavine.duckdetector.features.zygisk.presentation.ZygiskUiStage
import com.eltavine.duckdetector.features.zygisk.presentation.ZygiskUiState
import com.eltavine.duckdetector.features.zygisk.presentation.ZygiskViewModel
import com.eltavine.duckdetector.ui.shell.AppDestination
import com.eltavine.duckdetector.ui.shell.DetectorResultNoticeDialog
import com.eltavine.duckdetector.ui.shell.ScreenCaptureNoticeDialog
import com.eltavine.duckdetector.ui.shell.ScreenCaptureNoticeEffect
import com.eltavine.duckdetector.ui.shell.attentionDetectorTitles
import com.eltavine.duckdetector.ui.shell.FloatingAppTabSwitcher
import com.eltavine.duckdetector.ui.shell.StartupGateState
import com.eltavine.duckdetector.ui.shell.StartupPackageVisibilityState
import com.eltavine.duckdetector.ui.shell.StartupPolicyScreen
import com.eltavine.duckdetector.ui.shell.resolveStartupGateState
import com.eltavine.duckdetector.ui.shell.shouldShowDetectorResultNotice
import com.eltavine.duckdetector.ui.shell.shouldCreateDetectorViewModels
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun DuckDetectorApp() {
    val blacklistMatch = remember { DeviceBlacklist.matchCurrentDevice() }
    if (blacklistMatch != null) {
        Surface {
            BlockedDeviceScreen(
                match = blacklistMatch,
                modifier = Modifier.fillMaxSize(),
            )
        }
        return
    }

    val context = LocalContext.current
    val appContext = context.applicationContext
    val agreementStore = remember(appContext) { AgreementAcceptanceStore.getInstance(appContext) }
    val consentStore = remember(appContext) { TeeNetworkConsentStore.getInstance(appContext) }
    val notificationConsentStore = remember(appContext) {
        ScanNotificationConsentStore.getInstance(appContext)
    }
    val packageVisibilityReviewStore = remember(appContext) {
        PackageVisibilityReviewStore.getInstance(appContext)
    }
    val agreementPrefs by produceState<AgreementAcceptancePrefs?>(
        initialValue = null,
        key1 = agreementStore,
    ) {
        agreementStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val agreementAccepted = agreementPrefs?.accepted == true
    val teePrefs by produceState<TeeNetworkPrefs?>(
        initialValue = null,
        key1 = consentStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        consentStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val notificationPrefs by produceState<ScanNotificationPrefs?>(
        initialValue = null,
        key1 = notificationConsentStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        notificationConsentStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val packageVisibilityReviewPrefs by produceState<PackageVisibilityReviewPrefs?>(
        initialValue = null,
        key1 = packageVisibilityReviewStore,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        packageVisibilityReviewStore.prefs.collect { currentPrefs ->
            value = currentPrefs
        }
    }
    val packageVisibilityState by produceState<StartupPackageVisibilityState?>(
        initialValue = null,
        key1 = appContext,
        key2 = agreementAccepted,
    ) {
        if (!agreementAccepted) {
            value = null
            return@produceState
        }
        value = withContext(Dispatchers.IO) {
            val installedPackages =
                InstalledPackageVisibilityChecker.getInstalledPackages(appContext)
            val installedPackageCount = installedPackages.size
            val visibility = InstalledPackageVisibilityChecker.detect(
                context = appContext,
                installedPackageCount = installedPackageCount,
            )
            StartupPackageVisibilityState(
                visibility = visibility,
                visiblePackageCount = installedPackageCount,
                suspiciouslyLowInventory = InstalledPackageVisibilityChecker
                    .hasSuspiciouslyLowInventory(
                        visibility = visibility,
                        installedPackageCount = installedPackageCount,
                    ),
            )
        }
    }
    var notificationPermissionState by remember {
        mutableStateOf(ScanNotificationPermissions.read(appContext))
    }
    val gateState = remember(
        teePrefs,
        notificationPrefs,
        notificationPermissionState,
        packageVisibilityState,
        packageVisibilityReviewPrefs,
    ) {
        resolveStartupGateState(
            teePrefs = teePrefs,
            notificationPrefs = notificationPrefs,
            notificationPermissionState = notificationPermissionState,
            packageVisibilityLoaded = packageVisibilityState != null &&
                    packageVisibilityReviewPrefs != null,
            packageVisibility = packageVisibilityState?.visibility
                ?: com.eltavine.duckdetector.core.packagevisibility.InstalledPackageVisibility.UNKNOWN,
            packageVisibilityReviewAcknowledged =
                packageVisibilityReviewPrefs?.restrictedInventoryAcknowledged == true,
        )
    }
    val startupPoliciesReady = shouldCreateDetectorViewModels(gateState)
    val requiresAlphaAcknowledgement = BuildConfig.isAlphaVersion
    var alphaAcknowledged by rememberSaveable(BuildConfig.VERSION_NAME) {
        mutableStateOf(false)
    }
    var destination by rememberSaveable { mutableStateOf(AppDestination.MAIN) }
    var screenCaptureNoticeEventId by remember { mutableLongStateOf(0L) }
    val scope = rememberCoroutineScope()
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) {
        notificationPermissionState = ScanNotificationPermissions.read(appContext)
        scope.launch {
            notificationConsentStore.markNotificationsPrompted()
        }
    }
    val liveUpdateSettingsLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult(),
    ) {
        notificationPermissionState = ScanNotificationPermissions.read(appContext)
        if (notificationPermissionState.liveUpdatesGranted) {
            scope.launch {
                notificationConsentStore.markLiveUpdatesPrompted()
            }
        }
    }

    LaunchedEffect(notificationPrefs, notificationPermissionState) {
        val prefs = notificationPrefs ?: return@LaunchedEffect
        if (notificationPermissionState.notificationsGranted && !prefs.notificationsPrompted) {
            notificationConsentStore.markNotificationsPrompted()
        }
        if (notificationPermissionState.liveUpdatesGranted && !prefs.liveUpdatesPrompted) {
            notificationConsentStore.markLiveUpdatesPrompted()
        }
    }

    Surface {
        Box(modifier = Modifier.fillMaxSize()) {
            ScreenCaptureNoticeEffect(
                onScreenCaptured = {
                    screenCaptureNoticeEventId += 1L
                },
            )

            when {
                agreementPrefs == null -> {
                    StartupBootstrapLoadingScreen(modifier = Modifier.fillMaxSize())
                }

                !agreementAccepted -> {
                    AgreementScreen(
                        onAgree = {
                            scope.launch {
                                agreementStore.accept()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }

                startupPoliciesReady -> {
                    AppReadyShell(
                        destination = destination,
                        onSelectDestination = { selected -> destination = selected },
                        networkPrefs = requireNotNull(teePrefs),
                        consentStore = consentStore,
                        notificationPermissionState = notificationPermissionState,
                    )
                }

                else -> {
                    StartupPolicyScreen(
                        gateState = gateState,
                        notificationPrefs = notificationPrefs,
                        notificationPermissionState = notificationPermissionState,
                        teePrefs = teePrefs,
                        packageVisibilityState = packageVisibilityState,
                        packageVisibilityReviewAcknowledged =
                            packageVisibilityReviewPrefs?.restrictedInventoryAcknowledged == true,
                        onAllowNotifications = {
                            if (Build.VERSION.SDK_INT >= 33) {
                                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                            } else {
                                scope.launch {
                                    notificationConsentStore.markNotificationsPrompted()
                                }
                            }
                        },
                        onSkipNotifications = {
                            scope.launch {
                                notificationConsentStore.markNotificationsPrompted()
                            }
                        },
                        onOpenLiveUpdateSettings = {
                            val intent = ScanNotificationPermissions
                                .appNotificationPromotionSettingsIntent(appContext)
                            val canOpenSettings =
                                intent.resolveActivity(appContext.packageManager) != null
                            if (canOpenSettings) {
                                liveUpdateSettingsLauncher.launch(intent)
                            } else {
                                scope.launch {
                                    notificationConsentStore.markLiveUpdatesPrompted()
                                }
                            }
                        },
                        onUseRegularNotifications = {
                            scope.launch {
                                notificationConsentStore.markLiveUpdatesPrompted()
                            }
                        },
                        onAllowCrlNetwork = {
                            scope.launch {
                                consentStore.setConsent(true)
                            }
                        },
                        onUseLocalCrlOnly = {
                            scope.launch {
                                consentStore.setConsent(false)
                            }
                        },
                        onAcknowledgePackageVisibility = {
                            scope.launch {
                                packageVisibilityReviewStore.acknowledgeRestrictedInventory()
                            }
                        },
                        modifier = Modifier.fillMaxSize(),
                    )
                }
            }

            ScreenshotWatermarkOverlay()

            if (agreementAccepted && startupPoliciesReady) {
                AlphaBuildBanner()
            }

            AlphaBuildWarningOverlay(
                forceVisible = agreementAccepted &&
                        startupPoliciesReady &&
                        requiresAlphaAcknowledgement &&
                        !alphaAcknowledged,
                onDismissed = {
                    alphaAcknowledged = true
                },
            )

            if (screenCaptureNoticeEventId > 0L) {
                ScreenCaptureNoticeDialog(
                    noticeInstanceKey = screenCaptureNoticeEventId,
                    onDismiss = {
                        screenCaptureNoticeEventId = 0L
                    },
                )
            }
        }
    }
}

@Composable
private fun AppReadyShell(
    destination: AppDestination,
    onSelectDestination: (AppDestination) -> Unit,
    networkPrefs: TeeNetworkPrefs,
    consentStore: TeeNetworkConsentStore,
    notificationPermissionState: com.eltavine.duckdetector.core.notifications.ScanNotificationPermissionState,
) {
    val context = LocalContext.current
    val appContext = context.applicationContext
    val scope = rememberCoroutineScope()
    val notifier = remember(appContext) { ScanProgressNotifier(appContext) }
    val bootloaderFactory = remember(context) { BootloaderViewModel.factory(context) }
    val teeFactory = remember(context) { TeeViewModel.factory(context) }
    val customRomFactory = remember(context) { CustomRomViewModel.factory(context) }
    val dangerousAppsFactory = remember(context) { DangerousAppsViewModel.factory(context) }
    val deviceInfoFactory = remember(context) { DeviceInfoViewModel.factory(context) }
    val kernelCheckFactory = remember { KernelCheckViewModel.factory() }
    val lsposedFactory = remember(context) { LSPosedViewModel.factory(context) }
    val memoryFactory = remember { MemoryViewModel.factory() }
    val mountFactory = remember { MountViewModel.factory() }
    val nativeRootFactory = remember(context) { NativeRootViewModel.factory(context) }
    val playIntegrityFixFactory = remember { PlayIntegrityFixViewModel.factory() }
    val selinuxFactory = remember(context) { SelinuxViewModel.factory(context) }
    val suFactory = remember { SuViewModel.factory() }
    val systemPropertiesFactory = remember { SystemPropertiesViewModel.factory() }
    val virtualizationFactory = remember(context) { VirtualizationViewModel.factory(context) }
    val zygiskFactory = remember(context) { ZygiskViewModel.factory(context) }
    val bootloaderViewModel: BootloaderViewModel = viewModel(factory = bootloaderFactory)
    val teeViewModel: TeeViewModel = viewModel(factory = teeFactory)
    val customRomViewModel: CustomRomViewModel = viewModel(factory = customRomFactory)
    val dangerousAppsViewModel: DangerousAppsViewModel = viewModel(factory = dangerousAppsFactory)
    val deviceInfoViewModel: DeviceInfoViewModel = viewModel(factory = deviceInfoFactory)
    val kernelCheckViewModel: KernelCheckViewModel = viewModel(factory = kernelCheckFactory)
    val lsposedViewModel: LSPosedViewModel = viewModel(factory = lsposedFactory)
    val memoryViewModel: MemoryViewModel = viewModel(factory = memoryFactory)
    val mountViewModel: MountViewModel = viewModel(factory = mountFactory)
    val nativeRootViewModel: NativeRootViewModel = viewModel(factory = nativeRootFactory)
    val playIntegrityFixViewModel: PlayIntegrityFixViewModel =
        viewModel(factory = playIntegrityFixFactory)
    val selinuxViewModel: SelinuxViewModel = viewModel(factory = selinuxFactory)
    val suViewModel: SuViewModel = viewModel(factory = suFactory)
    val systemPropertiesViewModel: SystemPropertiesViewModel =
        viewModel(factory = systemPropertiesFactory)
    val virtualizationViewModel: VirtualizationViewModel =
        viewModel(factory = virtualizationFactory)
    val zygiskViewModel: ZygiskViewModel = viewModel(factory = zygiskFactory)
    val teeUiState by teeViewModel.uiState.collectAsState()
    val customRomUiState by customRomViewModel.uiState.collectAsState()
    val dangerousAppsUiState by dangerousAppsViewModel.uiState.collectAsState()
    val deviceInfoUiState by deviceInfoViewModel.uiState.collectAsState()
    val kernelCheckUiState by kernelCheckViewModel.uiState.collectAsState()
    val lsposedUiState by lsposedViewModel.uiState.collectAsState()
    val memoryUiState by memoryViewModel.uiState.collectAsState()
    val mountUiState by mountViewModel.uiState.collectAsState()
    val nativeRootUiState by nativeRootViewModel.uiState.collectAsState()
    val playIntegrityFixUiState by playIntegrityFixViewModel.uiState.collectAsState()
    val selinuxUiState by selinuxViewModel.uiState.collectAsState()
    val suUiState by suViewModel.uiState.collectAsState()
    val systemPropertiesUiState by systemPropertiesViewModel.uiState.collectAsState()
    val virtualizationUiState by virtualizationViewModel.uiState.collectAsState()
    val zygiskUiState by zygiskViewModel.uiState.collectAsState()
    val bootloaderUiState by bootloaderViewModel.uiState.collectAsState()
    val contributions = remember(
        bootloaderUiState,
        teeUiState,
        customRomUiState,
        dangerousAppsUiState,
        deviceInfoUiState,
        kernelCheckUiState,
        lsposedUiState,
        memoryUiState,
        mountUiState,
        nativeRootUiState,
        playIntegrityFixUiState,
        selinuxUiState,
        suUiState,
        systemPropertiesUiState,
        virtualizationUiState,
        zygiskUiState,
    ) {
        listOf(
            buildBootloaderContribution(bootloaderUiState),
            buildCustomRomContribution(customRomUiState),
            buildDangerousAppsContribution(dangerousAppsUiState),
            buildKernelCheckContribution(kernelCheckUiState),
            buildLsposedContribution(lsposedUiState),
            buildMemoryContribution(memoryUiState),
            buildMountContribution(mountUiState),
            buildNativeRootContribution(nativeRootUiState),
            buildPlayIntegrityFixContribution(playIntegrityFixUiState),
            buildSelinuxContribution(selinuxUiState),
            buildSuContribution(suUiState),
            buildSystemPropertiesContribution(systemPropertiesUiState),
            buildTeeContribution(teeUiState),
            buildVirtualizationContribution(virtualizationUiState),
            buildZygiskContribution(zygiskUiState),
        )
    }
    val isDashboardLoading = contributions.any { !it.ready }
    var dashboardScanStartedAt by remember { mutableLongStateOf(SystemClock.elapsedRealtime()) }
    var dashboardScanFinishedAt by remember { mutableStateOf<Long?>(null) }

    LaunchedEffect(isDashboardLoading) {
        if (isDashboardLoading) {
            if (dashboardScanFinishedAt != null) {
                dashboardScanStartedAt = SystemClock.elapsedRealtime()
                dashboardScanFinishedAt = null
            }
        } else if (dashboardScanFinishedAt == null) {
            dashboardScanFinishedAt = SystemClock.elapsedRealtime()
        }
    }

    val dashboardScanDurationMillis = dashboardScanFinishedAt
        ?.minus(dashboardScanStartedAt)
        ?.coerceAtLeast(0L)

    val dashboardState = remember(
        contributions,
        dashboardScanDurationMillis,
        isDashboardLoading,
        deviceInfoUiState,
        bootloaderUiState,
        teeUiState,
        customRomUiState,
        dangerousAppsUiState,
        kernelCheckUiState,
        lsposedUiState,
        memoryUiState,
        mountUiState,
        nativeRootUiState,
        playIntegrityFixUiState,
        selinuxUiState,
        suUiState,
        systemPropertiesUiState,
        virtualizationUiState,
        zygiskUiState,
    ) {
        DashboardUiState(
            overview = buildDashboardOverview(
                contributions = contributions,
                scanDurationMillis = dashboardScanDurationMillis,
            ),
            topFindings = buildDashboardFindings(contributions),
            detectorCards = sortDashboardDetectorCards(
                listOf(
                    DashboardDetectorCardEntry.Bootloader(bootloaderUiState.cardModel),
                    DashboardDetectorCardEntry.CustomRom(customRomUiState.cardModel),
                    DashboardDetectorCardEntry.DangerousApps(dangerousAppsUiState.cardModel),
                    DashboardDetectorCardEntry.KernelCheck(kernelCheckUiState.cardModel),
                    DashboardDetectorCardEntry.LSPosed(lsposedUiState.cardModel),
                    DashboardDetectorCardEntry.Memory(memoryUiState.cardModel),
                    DashboardDetectorCardEntry.Mount(mountUiState.cardModel),
                    DashboardDetectorCardEntry.NativeRoot(nativeRootUiState.cardModel),
                    DashboardDetectorCardEntry.PlayIntegrityFix(playIntegrityFixUiState.cardModel),
                    DashboardDetectorCardEntry.Selinux(selinuxUiState.cardModel),
                    DashboardDetectorCardEntry.Su(suUiState.cardModel),
                    DashboardDetectorCardEntry.SystemProperties(systemPropertiesUiState.cardModel),
                    DashboardDetectorCardEntry.Tee(teeUiState.cardModel),
                    DashboardDetectorCardEntry.Virtualization(virtualizationUiState.cardModel),
                    DashboardDetectorCardEntry.Zygisk(zygiskUiState.cardModel),
                ),
            ),
            deviceInfoCard = deviceInfoUiState.cardModel,
            isLoading = isDashboardLoading,
        )
    }
    val settingsState = remember(networkPrefs.consentGranted) {
        SettingsUiState(
            isCrlNetworkingEnabled = networkPrefs.consentGranted,
            versionName = BuildConfig.VERSION_NAME,
            versionCode = BuildConfig.VERSION_CODE,
            buildTimeUtc = BuildConfig.BUILD_TIME_UTC,
            buildHash = BuildConfig.BUILD_HASH,
        )
    }
    val detectorResultNoticeKey = remember(
        isDashboardLoading,
        dashboardState.overview.status,
        dashboardState.overview.summary,
        dashboardState.overview.metrics,
    ) {
        if (!shouldShowDetectorResultNotice(isDashboardLoading, dashboardState.overview.status)) {
            null
        } else {
            buildString {
                append(dashboardState.overview.headline)
                append('|')
                append(dashboardState.overview.summary)
                dashboardState.overview.metrics.forEach { metric ->
                    append('|')
                    append(metric.label)
                    append('=')
                    append(metric.value)
                }
            }
        }
    }
    var dismissedDetectorResultNoticeKey by rememberSaveable { mutableStateOf<String?>(null) }
    val detectorTitlesNeedingAttention = remember(contributions) {
        attentionDetectorTitles(contributions)
    }
    var pendingAttentionExpansionTitles by rememberSaveable { mutableStateOf(emptyList<String>()) }

    LaunchedEffect(detectorResultNoticeKey, detectorTitlesNeedingAttention) {
        if (detectorResultNoticeKey == null) {
            dismissedDetectorResultNoticeKey = null
            pendingAttentionExpansionTitles = emptyList()
        } else {
            pendingAttentionExpansionTitles = detectorTitlesNeedingAttention.toList()
        }
    }

    val notificationSnapshot = remember(
        contributions.size,
        contributions.count { it.ready },
        dashboardState.overview,
        isDashboardLoading,
    ) {
        ScanProgressNotificationSnapshot(
            totalDetectorCount = contributions.size,
            readyDetectorCount = contributions.count { it.ready },
            dashboardOverview = dashboardState.overview,
            scanning = isDashboardLoading,
        )
    }

    LaunchedEffect(notificationPermissionState, notificationSnapshot) {
        notifier.update(
            permissionState = notificationPermissionState,
            snapshot = notificationSnapshot,
        )
    }

    Box(modifier = Modifier.fillMaxSize()) {
        when (destination) {
            AppDestination.MAIN -> {
                CompositionLocalProvider(
                    LocalDetectorAutoExpansionDirective provides DetectorAutoExpansionDirective(
                        titles = pendingAttentionExpansionTitles.toSet(),
                        onConsumed = { title ->
                            pendingAttentionExpansionTitles =
                                pendingAttentionExpansionTitles.filterNot { it == title }
                        },
                    ),
                ) {
                    DashboardScreen(
                        uiState = dashboardState,
                        showTeeDetailsDialog = teeUiState.showDetailsDialog,
                        showTeeCertificatesDialog = teeUiState.showCertificatesDialog,
                        onTeeExpandedChange = teeViewModel::onExpandedChange,
                        onTeeFooterAction = teeViewModel::onFooterAction,
                        onDismissTeeDetails = teeViewModel::dismissDetails,
                        onDismissTeeCertificates = teeViewModel::dismissCertificates,
                    )
                }
            }

            AppDestination.SETTINGS -> {
                SettingsScreen(
                    uiState = settingsState,
                    onCrlNetworkingChange = { enabled ->
                        scope.launch {
                            consentStore.setConsent(enabled)
                            teeViewModel.rescan()
                        }
                    },
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }

        FloatingAppTabSwitcher(
            selectedDestination = destination,
            onSelectDestination = onSelectDestination,
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .padding(end = 20.dp, bottom = 28.dp),
        )

        if (
            detectorResultNoticeKey != null &&
            detectorResultNoticeKey != dismissedDetectorResultNoticeKey
        ) {
            DetectorResultNoticeDialog(
                onDismiss = {
                    dismissedDetectorResultNoticeKey = detectorResultNoticeKey
                },
            )
        }
    }
}

@Composable
private fun StartupBootstrapLoadingScreen(
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            CircularProgressIndicator()
            Text(
                text = "Preparing startup",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = "Loading agreement state before startup policy review.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private fun buildBootloaderContribution(
    bootloaderUiState: BootloaderUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "bootloader",
        title = bootloaderUiState.cardModel.title,
        status = bootloaderUiState.cardModel.status,
        headline = bootloaderUiState.cardModel.verdict,
        summary = bootloaderUiState.cardModel.summary,
        ready = bootloaderUiState.stage != BootloaderUiStage.LOADING,
    )
}

private fun buildCustomRomContribution(
    customRomUiState: CustomRomUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "custom_rom",
        title = customRomUiState.cardModel.title,
        status = customRomUiState.cardModel.status,
        headline = customRomUiState.cardModel.verdict,
        summary = customRomUiState.cardModel.summary,
        ready = customRomUiState.stage != CustomRomUiStage.LOADING,
    )
}

private fun buildSelinuxContribution(
    selinuxUiState: SelinuxUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "selinux",
        title = selinuxUiState.cardModel.title,
        status = selinuxUiState.cardModel.status,
        headline = selinuxUiState.cardModel.verdict,
        summary = selinuxUiState.cardModel.summary,
        ready = selinuxUiState.stage != SelinuxUiStage.LOADING,
    )
}

private fun buildKernelCheckContribution(
    kernelCheckUiState: KernelCheckUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "kernel_check",
        title = kernelCheckUiState.cardModel.title,
        status = kernelCheckUiState.cardModel.status,
        headline = kernelCheckUiState.cardModel.verdict,
        summary = kernelCheckUiState.cardModel.summary,
        ready = kernelCheckUiState.stage != KernelCheckUiStage.LOADING,
    )
}

private fun buildMountContribution(
    mountUiState: MountUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "mount",
        title = mountUiState.cardModel.title,
        status = mountUiState.cardModel.status,
        headline = mountUiState.cardModel.verdict,
        summary = mountUiState.cardModel.summary,
        ready = mountUiState.stage != MountUiStage.LOADING,
    )
}

private fun buildMemoryContribution(
    memoryUiState: MemoryUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "memory",
        title = memoryUiState.cardModel.title,
        status = memoryUiState.cardModel.status,
        headline = memoryUiState.cardModel.verdict,
        summary = memoryUiState.cardModel.summary,
        ready = memoryUiState.stage != MemoryUiStage.LOADING,
    )
}

private fun buildLsposedContribution(
    lsposedUiState: LSPosedUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "lsposed",
        title = lsposedUiState.cardModel.title,
        status = lsposedUiState.cardModel.status,
        headline = lsposedUiState.cardModel.verdict,
        summary = lsposedUiState.cardModel.summary,
        ready = lsposedUiState.stage != LSPosedUiStage.LOADING,
    )
}

private fun buildPlayIntegrityFixContribution(
    playIntegrityFixUiState: PlayIntegrityFixUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "play_integrity_fix",
        title = playIntegrityFixUiState.cardModel.title,
        status = playIntegrityFixUiState.cardModel.status,
        headline = playIntegrityFixUiState.cardModel.verdict,
        summary = playIntegrityFixUiState.cardModel.summary,
        ready = playIntegrityFixUiState.stage != PlayIntegrityFixUiStage.LOADING,
    )
}

private fun buildNativeRootContribution(
    nativeRootUiState: NativeRootUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "native_root",
        title = nativeRootUiState.cardModel.title,
        status = nativeRootUiState.cardModel.status,
        headline = nativeRootUiState.cardModel.verdict,
        summary = nativeRootUiState.cardModel.summary,
        ready = nativeRootUiState.stage != NativeRootUiStage.LOADING,
    )
}

private fun buildDangerousAppsContribution(
    dangerousAppsUiState: DangerousAppsUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "dangerous_apps",
        title = dangerousAppsUiState.cardModel.title,
        status = dangerousAppsUiState.cardModel.status,
        headline = dangerousAppsUiState.cardModel.verdict,
        summary = dangerousAppsUiState.cardModel.summary,
        ready = dangerousAppsUiState.stage != DangerousAppsUiStage.LOADING,
    )
}

private fun buildTeeContribution(
    teeUiState: TeeUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "tee",
        title = teeUiState.cardModel.title,
        status = teeUiState.cardModel.status,
        headline = teeUiState.cardModel.verdict,
        summary = teeUiState.cardModel.summary,
        ready = teeUiState.stage != TeeUiStage.LOADING,
    )
}

private fun buildSuContribution(
    suUiState: SuUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "su",
        title = suUiState.cardModel.title,
        status = suUiState.cardModel.status,
        headline = suUiState.cardModel.verdict,
        summary = suUiState.cardModel.summary,
        ready = suUiState.stage != SuUiStage.LOADING,
    )
}

private fun buildSystemPropertiesContribution(
    systemPropertiesUiState: SystemPropertiesUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "system_properties",
        title = systemPropertiesUiState.cardModel.title,
        status = systemPropertiesUiState.cardModel.status,
        headline = systemPropertiesUiState.cardModel.verdict,
        summary = systemPropertiesUiState.cardModel.summary,
        ready = systemPropertiesUiState.stage != SystemPropertiesUiStage.LOADING,
    )
}

private fun buildZygiskContribution(
    zygiskUiState: ZygiskUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "zygisk",
        title = zygiskUiState.cardModel.title,
        status = zygiskUiState.cardModel.status,
        headline = zygiskUiState.cardModel.verdict,
        summary = zygiskUiState.cardModel.summary,
        ready = zygiskUiState.stage != ZygiskUiStage.LOADING,
    )
}

private fun buildVirtualizationContribution(
    virtualizationUiState: VirtualizationUiState,
): DashboardDetectorContribution {
    return DashboardDetectorContribution(
        id = "virtualization",
        title = virtualizationUiState.cardModel.title,
        status = virtualizationUiState.cardModel.status,
        headline = virtualizationUiState.cardModel.verdict,
        summary = virtualizationUiState.cardModel.summary,
        ready = virtualizationUiState.stage != VirtualizationUiStage.LOADING,
    )
}
