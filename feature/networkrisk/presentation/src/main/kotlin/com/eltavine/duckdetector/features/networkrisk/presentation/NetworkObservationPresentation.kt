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

package com.eltavine.duckdetector.features.networkrisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.networkrisk.domain.*
import com.eltavine.duckdetector.features.networkrisk.presentation.model.NetworkRiskDetailRowModel

internal val ObservationState.label: String get() = when (this) {
    ObservationState.OBSERVED -> "Observed"
    ObservationState.NOT_OBSERVED -> "Not observed"
    ObservationState.UNAVAILABLE -> "Unavailable"
    ObservationState.PERMISSION_LIMITED -> "Permission limited"
    ObservationState.UNSUPPORTED -> "Unsupported"
    ObservationState.INCONCLUSIVE -> "Inconclusive"
}

internal fun row(label: String, state: ObservationState, detail: String, value: String = state.label, failure: ProbeFailure? = null, warning: Boolean = false): NetworkRiskDetailRowModel =
    NetworkRiskDetailRowModel(label, value,
        if (warning && state == ObservationState.OBSERVED) DetectorStatus.warning() else state.toDetectorStatus(failure), detail)

internal fun ProxyConfiguration.describe(): String = when (kind) {
    ProxyKind.PAC -> "PAC configured; URL omitted; request-level proxy selection not evaluated."
    ProxyKind.STATIC -> "HTTP proxy configured; port $port; $exclusionCount exclusions; host omitted."
}

internal fun ProbeFailure?.describe(): String = when (this) {
    ProbeFailure.ACCESS_DENIED -> "Access denied."
    ProbeFailure.PLATFORM_FAILURE -> "Platform query or read failed."
    ProbeFailure.DISAPPEARED -> "Network disappeared or its properties became inaccessible."
    ProbeFailure.READ_LIMIT -> "Collection budget exceeded."
    ProbeFailure.INVALID_METADATA -> "Metadata is malformed, ambiguous or not a regular file."
    ProbeFailure.NOT_EVALUATED -> "Not evaluated."
    null -> ""
}
