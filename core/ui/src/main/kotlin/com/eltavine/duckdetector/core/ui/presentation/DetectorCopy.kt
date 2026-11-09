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

/**
 * Resolves known detector copy at the Android UI boundary.
 *
 * Detector presentation modules intentionally remain plain Kotlin/JVM and therefore cannot read
 * Android resources. Their stable English copy is used as a lookup key here; raw evidence,
 * package names, property values, paths, and unknown diagnostic text pass through unchanged.
 */
@Composable
public fun localizeDetectorCopy(text: String): String {
    // Preserve machine-facing evidence and diagnostic records verbatim. These strings are often
    // compared with kernel logs, policy rules, probe output, or upstream protocol documentation.
    if (text.contains("Evidence source=") ||
        text.contains("Observed edge:") ||
        text.contains("Controlled app_zygote writes repeatedly recognized privileged contexts:") ||
        text.contains("DirtySepolicy 2.2 compatibility:")
    ) return text

    localizeDetectorCopyStructured(text)?.let { return it }

    detectorCopyLabelResources[text]?.let { return stringResource(it) }
    detectorCopyValueResources[text]?.let { return stringResource(it) }
    detectorCopyDetailResources[text]?.let { return stringResource(it) }

    // Some card summaries concatenate several independently-authored sentences. Translate the
    // known sentences in place while preserving dynamic values and raw diagnostic evidence.
    var localizedComposite = text
    mapOf(
        "caller default" to R.string.detector_copy_value_network_caller_default,
        "process bound" to R.string.detector_copy_value_network_process_bound,
        "other visible" to R.string.detector_copy_value_network_other_visible,
    ).forEach { (source, resource) ->
        localizedComposite = localizedComposite.replace(source, stringResource(resource))
    }
    detectorCopyDetailResources.entries
        .asSequence()
        .filter { (source, _) -> source.length >= 36 && localizedComposite.contains(source) }
        .sortedWith(compareByDescending<Map.Entry<String, Int>> { it.key.length }.thenBy { it.key })
        .forEach { (source, resource) ->
            localizedComposite = localizedComposite.replace(source, stringResource(resource))
        }
    if (localizedComposite != text) return localizedComposite

    return localizeDetectorCopyFallback(text)
}
