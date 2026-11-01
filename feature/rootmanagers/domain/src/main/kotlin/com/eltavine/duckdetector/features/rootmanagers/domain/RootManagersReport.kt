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

package com.eltavine.duckdetector.features.rootmanagers.domain

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility

enum class RootManagersStage {
    LOADING,
    READY,
    FAILED,
}

/**
 * Whether the launcher enumeration actually ran and produced a profile list.
 *
 * This is what separates "the enumeration looked and matched nothing" from "the enumeration never
 * ran": only [EVALUATED] lets an empty [RootManagersReport.entries] mean the profiles were searched.
 */
enum class RootManagersEnumerationState {
    /** Profiles were enumerated; an empty entry list means nothing matched, not that nothing was seen. */
    EVALUATED,

    /** The platform refused or failed the enumeration, so absence of entries proves nothing. */
    UNAVAILABLE,

    /** No profile was returned, so there was nothing to enumerate; absence of entries proves nothing. */
    UNDECIDABLE,
}

data class RootManagersReport(
    val stage: RootManagersStage,
    val enumerationState: RootManagersEnumerationState,
    val profileScans: List<RootManagersProfileScan> = emptyList(),
    val entries: List<RootManagerEntry> = emptyList(),
    val coverage: RootManagersCoverage = RootManagersCoverage(),
    val issues: List<String> = emptyList(),
    val installerCanary: InstallerCanaryObservation = InstallerCanaryObservation(),
) {
    /** Profiles the enumeration actually read; a denied or empty profile is recorded but not counted. */
    val profilesSearched: Int
        get() = profileScans.count { scan -> scan.state == ProfileScanState.SEARCHED }

    val launcherActivitiesSeen: Int
        get() = profileScans.sumOf { scan -> scan.launcherActivitiesSeen }

    val appsChecked: Int
        get() = profileScans.sumOf { scan -> scan.appsChecked }

    /**
     * Whether an empty result may read as clean: every returned profile was searched, the caller saw
     * itself where it should, PackageManager visibility is full, and certificates could be read.
     * Anything less is a partial evaluation, which is never reported as all clear.
     */
    val complete: Boolean
        get() = enumerationState == RootManagersEnumerationState.EVALUATED &&
            profileScans.isNotEmpty() &&
            profileScans.all { scan -> scan.state == ProfileScanState.SEARCHED } &&
            coverage.callerSelfObserved != false &&
            coverage.packageVisibility == InstalledPackageVisibility.FULL &&
            !coverage.certificatesUnavailable &&
            (installerCanary.state == InstallerCanaryState.DISABLED || installerCanary.evaluated)

    companion object {
        fun loading(): RootManagersReport = RootManagersReport(
            stage = RootManagersStage.LOADING,
            enumerationState = RootManagersEnumerationState.UNDECIDABLE,
        )

        fun failed(message: String): RootManagersReport = RootManagersReport(
            stage = RootManagersStage.FAILED,
            enumerationState = RootManagersEnumerationState.UNAVAILABLE,
            issues = listOf(message),
        )

        fun evaluated(
            entries: List<RootManagerEntry>,
            profileScans: List<RootManagersProfileScan>,
            coverage: RootManagersCoverage,
            issues: List<String> = emptyList(),
        ): RootManagersReport = RootManagersReport(
            stage = RootManagersStage.READY,
            enumerationState = RootManagersEnumerationState.EVALUATED,
            profileScans = profileScans,
            entries = entries,
            coverage = coverage,
            issues = issues,
        )

        /**
         * The launcher enumeration failed; entries the caller-profile PackageManager sweep still
         * found are kept, because a manager seen there is present whatever the launcher path did.
         */
        fun unavailable(
            reason: String,
            entries: List<RootManagerEntry> = emptyList(),
            profileScans: List<RootManagersProfileScan> = emptyList(),
            coverage: RootManagersCoverage = RootManagersCoverage(),
            issues: List<String> = emptyList(),
        ): RootManagersReport = RootManagersReport(
            stage = RootManagersStage.READY,
            enumerationState = RootManagersEnumerationState.UNAVAILABLE,
            profileScans = profileScans,
            entries = entries,
            coverage = coverage,
            issues = listOf(reason) + issues,
        )

        fun undecidable(
            reason: String,
            entries: List<RootManagerEntry> = emptyList(),
            profileScans: List<RootManagersProfileScan> = emptyList(),
            coverage: RootManagersCoverage = RootManagersCoverage(),
            issues: List<String> = emptyList(),
        ): RootManagersReport = RootManagersReport(
            stage = RootManagersStage.READY,
            enumerationState = RootManagersEnumerationState.UNDECIDABLE,
            profileScans = profileScans,
            entries = entries,
            coverage = coverage,
            issues = listOf(reason) + issues,
        )
    }
}
