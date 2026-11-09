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

private val teeTrustSummary = Regex(
    """^Local trust path: (.+?), chain (verified|failed)(?:, (.+))?$""",
)

private val teePolicySignalCounts = Regex("""^(\d+) policy hard • (\d+) policy review • (\d+) local$""")

private val teeChainLayout = Regex("""^len (\d+) • ext (\d+) • trusted (#[1-9]\d*|n/a)$""")

private val teeVersions = Regex("""^attest (.+?) • keymaster (.+?) • Android (.+)$""")

@Composable
internal fun localizeTeeSummary(text: String): String? {
    teeVersions.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_tee_versions,
            match.groupValues[1],
            match.groupValues[2],
            match.groupValues[3],
        )
    }
    teeChainLayout.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_tee_chain_layout,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3],
        )
    }
    teePolicySignalCounts.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_tee_policy_signal_counts,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    return null
}

@Composable
internal fun localizeTeeTrustSummary(text: String): String? {
    teeTrustSummary.matchEntire(text)?.let { match ->
        val trustRoot = localizeDetectorCopy(match.groupValues[1])
        val chainState = localizeDetectorCopy(match.groupValues[2])
        val suffix = match.groupValues[3].takeIf(String::isNotBlank)
            ?.let { ", ${localizeDetectorCopy(it)}" }
            .orEmpty()
        return stringResource(
            R.string.detector_copy_card_tee_trust_path_template,
            trustRoot,
            chainState,
            suffix,
        )
    }
    return null
}
