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

package com.eltavine.duckdetector.features.dangerousapps.ui.model

import com.eltavine.duckdetector.core.ui.model.ContextItemModel
import com.eltavine.duckdetector.core.ui.model.DetectorStatus

data class DangerousAppsCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val headerFacts: List<DangerousAppsHeaderFactModel>,
    val hmaAlert: DangerousAppsHmaAlertModel? = null,
    val packageItems: List<DangerousAppsPackageItemModel>,
    val context: List<ContextItemModel>,
    val targetApps: List<DangerousAppsTargetAppModel>,
)

data class DangerousAppsHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
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
