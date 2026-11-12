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

package com.eltavine.duckdetector.core.ui.presentation

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.R

private val dangerousAppsSubtitle = Regex(
    """^(\d+) legacy targets(?: · (full|scoped) PM inventory)?(?: · (\d+) visible)?$""",
)

private val dangerousAppsVisibilityCount = Regex("""^(Full|Scoped) · (\d+)$""")

private val dangerousAppsRiskyPackageCount = Regex("""^(\d+) risky package\(s\) surfaced$""")

private val dangerousAppsSignalCount = Regex("""^(\d+) signal\(s\)$""")

private val dangerousAppsPackageHitCount = Regex("""^(\d+) package hit\(s\)$""")

private val dangerousAppsLegacyPackages = Regex("""^(\d+) legacy packages$""")

private val dangerousAppsMatchedSummary = Regex(
    """^Matched (\d+) package\(s\) across (\d+) category\(ies\)\. All package hits stay warning-level unless HMA concealment is present\.(?: PackageManager still exposed only (\d+) visible packages, which is unusually low and can happen under HMA-style whitelist filtering\.)?$""",
)

@Composable
internal fun localizeDangerousAppsCounts(text: String): String? {
    dangerousAppsRiskyPackageCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_dangerousapps_verdict_risky_packages, match.groupValues[1].toInt())
    }
    dangerousAppsMatchedSummary.matchEntire(text)?.let { match ->
        val base = stringResource(
            R.string.detector_copy_dangerousapps_summary_matched_packages,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
        val lowInventoryCount = match.groupValues[3]
        return if (lowInventoryCount.isEmpty()) base else {
            "$base ${stringResource(R.string.detector_copy_dangerousapps_summary_low_inventory, lowInventoryCount.toInt())}"
        }
    }
    dangerousAppsSignalCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_signal_count, match.groupValues[1].toInt())
    }
    dangerousAppsPackageHitCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_package_hit_count, match.groupValues[1].toInt())
    }
    dangerousAppsLegacyPackages.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_legacy_packages, match.groupValues[1].toInt())
    }
    return null
}

@Composable
internal fun localizeDangerousAppsSubtitle(text: String): String? {
    dangerousAppsSubtitle.matchEntire(text)?.let { match ->
        val parts = mutableListOf(
            stringResource(R.string.detector_copy_subtitle_dangerousapps_targets, match.groupValues[1].toInt()),
        )
        when (match.groupValues[2]) {
            "full" -> parts += stringResource(R.string.detector_copy_subtitle_dangerousapps_full_pm)
            "scoped" -> parts += stringResource(R.string.detector_copy_subtitle_dangerousapps_scoped_pm)
        }
        match.groupValues[3].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_dangerousapps_visible, it.toInt())
        }
        return parts.joinToString(" · ")
    }
    dangerousAppsVisibilityCount.matchEntire(text)?.let { match ->
        return "${localizeDetectorCopy(match.groupValues[1])} · ${match.groupValues[2]}"
    }
    return null
}
