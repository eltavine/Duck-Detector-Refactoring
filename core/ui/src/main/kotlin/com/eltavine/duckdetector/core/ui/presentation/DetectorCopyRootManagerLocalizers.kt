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

private val rootManagerConcealedSummary = Regex(
    """^Identified (\d+) root manager app\(s\); at least one disabled its launcher icon and is reachable only through app details\. (.+)$""",
)

private val rootManagersSubtitle = Regex("""^(\d+) matched · (\d+) apps checked · (\d+) profile\(s\) searched$""")

private val rootManagersAppsChecked = Regex("""^(\d+) apps checked$""")

private val rootManagersMatches = Regex("""^(\d+) match\(es\)$""")

private val rootManagersProfileStats = Regex("""^(\d+) apps checked · (\d+) match\(es\)$""")

private val countOfCount = Regex("""^(\d+) of (\d+)$""")

private val countReadFailed = Regex("""^(\d+) read · (\d+) failed$""")

private val profileUserLabel = Regex("""^user (\d+)$""")

private val rootManagersFoundSummary = Regex("""^Identified (\d+) root manager app\(s\) across (\d+) profile\(s\), (\d+) by a family kernel's manager key\. (.+)$""")

private val rootManagersCleanSummary = Regex("""^Checked (\d+) app\(s\) across (\d+) profile\(s\), including (\d+) signing certificates, and matched no root manager app\.$""")

private val rootManagersPartialSummary = Regex("""^No root manager matched, but (.+), so the absence of matches is not proof\.$""")

private val rootManagersPermissionOwnerSummary = Regex("""^(.+) declares the candidate KernelSU permission\. (.+)$""")

private val rootManagersEntryDetail = Regex("""^@user (\d+) · anchors: (.+?)(?: · signed with the (.+?) manager key)?(?: · payload: (.+?))?( · launcher icon hidden)?$""")

@Composable
internal fun localizeRootManagerSummary(text: String): String? {
    rootManagersPartialSummary.matchEntire(text)?.let { match ->
        val localizedGaps = mutableListOf<String>()
        for (gap in match.groupValues[1].split(", ")) {
            localizedGaps += localizeDetectorCopy(gap)
        }
        return stringResource(R.string.detector_copy_card_rootmanagers_partial, localizedGaps.joinToString("、"))
    }
    rootManagersSubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_rootmanagers,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    rootManagersAppsChecked.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_rootmanagers_apps_checked, match.groupValues[1].toInt())
    }
    rootManagersMatches.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_rootmanagers_matches, match.groupValues[1].toInt())
    }
    rootManagersProfileStats.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_rootmanagers_profile_stats,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
    }
    countOfCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_count_of_count, match.groupValues[1].toInt(), match.groupValues[2].toInt())
    }
    countReadFailed.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_count_read_failed, match.groupValues[1].toInt(), match.groupValues[2].toInt())
    }
    profileUserLabel.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_label_profile_user, match.groupValues[1].toInt())
    }
    rootManagersFoundSummary.matchEntire(text)?.let { match ->
        val summary = stringResource(
            R.string.detector_copy_card_rootmanagers_found,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
        return "$summary ${localizeDetectorCopy(match.groupValues[4])}"
    }
    rootManagersCleanSummary.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_card_rootmanagers_clean,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    rootManagersPermissionOwnerSummary.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_card_rootmanagers_permission_owner,
            match.groupValues[1],
            localizeDetectorCopy(match.groupValues[2]),
        )
    }
    rootManagersEntryDetail.matchEntire(text)?.let { match ->
        val localizedAnchors = StringBuilder()
        val anchorParts = match.groupValues[2].split(", ")
        for (index in anchorParts.indices) {
            if (index > 0) localizedAnchors.append(", ")
            localizedAnchors.append(localizeDetectorCopy(anchorParts[index]))
        }
        val anchors = localizedAnchors.toString()
        val signedWith = match.groupValues[3].takeIf(String::isNotEmpty)?.let {
            stringResource(R.string.detector_copy_value_rootmanagers_signed_with_key, it)
        }.orEmpty()
        val payload = match.groupValues[4].takeIf(String::isNotEmpty)?.let {
            stringResource(R.string.detector_copy_value_rootmanagers_payload, it)
        }.orEmpty()
        val iconHidden = if (match.groupValues[5].isNotEmpty()) {
            stringResource(R.string.detector_copy_value_rootmanagers_icon_hidden)
        } else {
            ""
        }
        return stringResource(
            R.string.detector_copy_value_rootmanagers_entry_detail,
            match.groupValues[1].toInt(),
            anchors,
            signedWith,
            payload,
            iconHidden,
        )
    }
    return null
}

@Composable
internal fun localizeRootManagerConcealedSummary(text: String): String? {
    rootManagerConcealedSummary.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return text
        return stringResource(
            R.string.detector_copy_card_rootmanagers_hidden_icon,
            count,
            localizeDetectorCopy(match.groupValues[2]),
        )
    }
    return null
}
