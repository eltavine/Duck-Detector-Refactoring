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

package com.eltavine.duckdetector.features.dangerousapps.presentation.model

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.report.DetectorHeadline

data class DangerousAppsCardModel(
    override val title: String,
    val subtitle: String,
    override val status: DetectorStatus,
    override val verdict: String,
    override val summary: String,
    val headerFacts: List<DangerousAppsHeaderFactModel>,
    val hmaAlert: DangerousAppsHmaAlertModel? = null,
    val packageItems: List<DangerousAppsPackageItemModel>,
    val context: List<DangerousAppsContextItemModel>,
    val targetApps: List<DangerousAppsTargetAppModel>,
) : DetectorHeadline {
    /** Rendering-only severity for the Packages section. */
    val packageSectionSeverity: DetectionSeverity?
        get() {
            val hidden = headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.HIDDEN }?.status?.severity
            val hits = headerFacts.firstOrNull { it.fact == DangerousAppsHeaderFact.HITS }?.status?.severity
            return when {
                hidden == DetectionSeverity.DANGER -> DetectionSeverity.DANGER
                hits == DetectionSeverity.WARNING -> DetectionSeverity.WARNING
                else -> null
            }
        }
}

/** The facts in the card's header, in the order the export lists them. */
enum class DangerousAppsHeaderFact(val label: String) {
    TARGETS("Targets"),
    PM("PM"),
    HITS("Hits"),
    HIDDEN("Hidden"),
}

data class DangerousAppsHeaderFactModel(
    val fact: DangerousAppsHeaderFact,
    val value: String,
    val status: DetectorStatus,
) {
    val label: String get() = fact.label
}

data class DangerousAppsContextItemModel(
    val label: String,
    val value: String,
)

data class DangerousAppsHmaAlertModel(
    val title: String,
    val summary: String,
    val hiddenPackages: List<DangerousAppsHiddenPackageItemModel>,
)

data class DangerousAppsHiddenPackageItemModel(
    val appName: String,
    val packageName: String,
    val methods: List<String>,
)

data class DangerousAppsPackageItemModel(
    val appName: String,
    val packageName: String,
    val methods: List<String>,
)

data class DangerousAppsTargetAppModel(
    val appName: String,
    val packageName: String,
    val category: String,
)
