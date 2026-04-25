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

package com.eltavine.duckdetector.features.tee.ui.model

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.tee.domain.TeeCertificateItem

enum class TeeFactIcon {
    TRUST,
    CERTIFICATE,
    NETWORK,
    RKP,
    KEY,
    BOOT,
    PATCH,
    DEVICE,
    APP,
    AUTH,
    KEYSTORE,
    TIMING,
    STRONGBOX,
    NATIVE,
    SOTER,
    WARNING,
}

data class TeeHeaderFactModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class TeeHighlightSignalModel(
    val label: String,
    val value: String,
    val status: DetectorStatus,
)

data class TeeFactRowModel(
    val icon: TeeFactIcon,
    val label: String,
    val value: String,
    val status: DetectorStatus,
    // 只给实现层透传隐藏复制载荷，展示层看到 null 就表示该行没有任何额外交互。
    // Only carries hidden copy payload through the UI model layer; null means the row has no extra interaction.
    val hiddenCopyText: String? = null,
)

data class TeeFactGroupModel(
    val title: String,
    val rows: List<TeeFactRowModel>,
)

data class TeeCertificateSummaryModel(
    val label: String,
    val count: String,
    val certificates: List<TeeCertificateItem>,
)

enum class TeeFooterActionId {
    RESCAN,
    DETAILS,
    CERTIFICATES,
}

data class TeeFooterActionModel(
    val id: TeeFooterActionId,
    val label: String,
    val counter: String? = null,
    val enabled: Boolean = true,
)

data class TeeNetworkStateModel(
    val label: String,
    val summary: String,
    val status: DetectorStatus,
)

data class TeeCardModel(
    val title: String,
    val subtitle: String,
    val status: DetectorStatus,
    val verdict: String,
    val summary: String,
    val isExpanded: Boolean,
    val headerFacts: List<TeeHeaderFactModel>,
    val highlightSignals: List<TeeHighlightSignalModel>,
    val factGroups: List<TeeFactGroupModel>,
    val certificateSummary: TeeCertificateSummaryModel,
    val actions: List<TeeFooterActionModel>,
    val networkState: TeeNetworkStateModel,
    val exportText: String,
    val rkpBadgeLabel: String? = null,
)
