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

package com.eltavine.duckdetector.features.lsposed.data.art

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedMethodOutcome
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class ArtMethodIntegrityResult(
    val available: Boolean = false,
    val mainSnapshot: ArtMethodSnapshot = ArtMethodSnapshot(),
    val isolatedSnapshot: ArtMethodSnapshot = ArtMethodSnapshot(),
    val sentinelBehaviorClean: Boolean = true,
    val signals: List<LSPosedSignal> = emptyList(),
    val detail: String = "",
) {
    val hitCount: Int
        get() = signals.size

    val outcome: LSPosedMethodOutcome
        get() = when {
            signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> LSPosedMethodOutcome.DETECTED
            signals.any { it.severity == LSPosedSignalSeverity.WARNING } -> LSPosedMethodOutcome.WARNING
            available -> LSPosedMethodOutcome.CLEAN
            else -> LSPosedMethodOutcome.SUPPORT
        }

    val summary: String
        get() = when {
            signals.any { it.severity == LSPosedSignalSeverity.DANGER } -> "${signals.count { it.severity == LSPosedSignalSeverity.DANGER }} strong"
            signals.isNotEmpty() -> "${signals.size} review"
            available -> "Clean"
            else -> "Unavailable"
        }
}

internal fun artSignal(
    id: String,
    label: String,
    value: String,
    severity: LSPosedSignalSeverity,
    detail: String,
): LSPosedSignal {
    return LSPosedSignal(
        id = "art_$id",
        label = label,
        value = value,
        group = LSPosedSignalGroup.RUNTIME,
        severity = severity,
        detail = detail,
        detailMonospace = detail.contains("0x") ||
                detail.contains("/apex/") ||
                detail.contains("/data/") ||
                detail.contains("memfd:") ||
                detail.contains("(deleted)"),
    )
}
