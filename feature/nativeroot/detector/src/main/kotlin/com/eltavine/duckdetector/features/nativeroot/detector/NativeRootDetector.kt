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

package com.eltavine.duckdetector.features.nativeroot.detector

import android.content.Context
import android.content.pm.ApplicationInfo
import com.eltavine.duckdetector.core.detector.Detector
import com.eltavine.duckdetector.core.detector.DetectorConsent
import com.eltavine.duckdetector.core.detector.DetectorScanner
import com.eltavine.duckdetector.core.detector.DetectorSpecificApi
import com.eltavine.duckdetector.core.evidence.DetectorId
import com.eltavine.duckdetector.core.report.DetectorReport
import com.eltavine.duckdetector.features.nativeroot.data.repository.NativeRootRepository
import com.eltavine.duckdetector.features.nativeroot.data.service.ThroneHuntWatchInstaller
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootReport
import com.eltavine.duckdetector.features.nativeroot.presentation.NativeRootCardModelMapper
import com.eltavine.duckdetector.features.nativeroot.presentation.model.NativeRootCardModel
import com.eltavine.duckdetector.features.nativeroot.presentation.toDetectorReport

/**
 * Native Root: looks for kernel-level root such as KernelSU, KernelPatch and SuSFS through
 * native probes, process and cgroup leaks, mount namespace drift, manager fingerprints,
 * temporary root artifacts and the KernelSU throne-hunt stimulus.
 *
 * Collected by [NativeRootRepository], judged by `NativeRootReport.toDetectorStatus()` in the
 * domain layer, and described by [NativeRootCardModelMapper].
 */
@DetectorSpecificApi
public object NativeRootDetector : Detector<NativeRootReport, NativeRootCardModel> {
    override val id: DetectorId = DetectorId("native_root")

    override val consents: List<DetectorConsent> =
        listOf(NativeRootSrcuTimingConsent)

    override fun createScanner(context: Context): DetectorScanner<NativeRootReport> = NativeRootRepository(context)

    override fun loadingReport(): NativeRootReport = NativeRootReport.loading()

    override fun describe(report: NativeRootReport): NativeRootCardModel = NativeRootCardModelMapper().map(report)

    override fun export(model: NativeRootCardModel): DetectorReport = model.toDetectorReport()

    /**
     * KernelSU's pkg_observer reacts to a /data/system/packages.list rewrite by running
     * track_throne -> search_manager("/data/app", 2), which opens and iterates every package
     * directory inode. Watching this package's own directory from app_zygote is what makes that
     * kernel-side traversal observable, so the watch is installed there rather than in the child.
     * Without the app zygote preload the throne-hunt carrier reports its collection as failed,
     * because the dedicated app_zygote preload state is unavailable.
     */
    override fun appZygotePreload(appInfo: ApplicationInfo) {
        ThroneHuntWatchInstaller.publish(ThroneHuntWatchInstaller.install(appInfo))
    }
}
