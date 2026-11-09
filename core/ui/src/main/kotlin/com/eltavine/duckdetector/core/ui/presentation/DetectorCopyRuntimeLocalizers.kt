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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.R

private val signalCount = Regex("""^(\d+) (.+?) signal\(s\)( need review)?$""")

private val zygiskSubtitle = Regex("""^(\d+) strong · (\d+) heuristic · (\d+) signal\(s\)$""")

private val memoryNativeSubtitle = Regex("""^(\d+) native detector families · current-process memory only$""")

private val virtualizationSubtitle = Regex("""^(\d+) env · (\d+) translation · (\d+) runtime(?: · (\d+) dex)?(?: · (\d+) uid)?(?: · (\d+) trap hit\(s\))?(?: · (\d+) host app\(s\))?$""")

private val lsposedSubtitle = Regex("""^(\d+) manager · (\d+) module · (\d+) native(?: · (\d+) policy)?$""")

private val nativeRootSubtitle = Regex("""^(\d+) paths · (\d+) proc entries · (\d+) cgroup dirs · (\d+) kernel sources · (\d+) props$""")

private val playIntegritySubtitle = Regex("""^(\d+) props · (\d+) hits · (\d+) mismatch · (\d+) traces$""")

private val heapBytes = Regex("""^(\d+) bytes$""")

@Composable
internal fun localizePlayIntegrityAndHeapSummary(text: String): String? {
    playIntegritySubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_playintegrityfix_counts,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
            match.groupValues[4].toInt(),
        )
    }
    heapBytes.matchEntire(text)?.let { match ->
        val bytes = match.groupValues[1].toLongOrNull() ?: return text
        return stringResource(R.string.detector_copy_value_bytes, bytes)
    }
    return null
}

@Composable
internal fun localizeNativeRootAndLsposedSummary(text: String): String? {
    nativeRootSubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_nativeroot_counts,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
            match.groupValues[4].toInt(),
            match.groupValues[5].toInt(),
        )
    }
    lsposedSubtitle.matchEntire(text)?.let { match ->
        val managers = match.groupValues[1].toInt()
        val modules = match.groupValues[2].toInt()
        val native = match.groupValues[3].toInt()
        val policy = match.groupValues[4]
        return if (policy.isEmpty()) {
            stringResource(R.string.detector_copy_subtitle_lsposed_counts, managers, modules, native)
        } else {
            stringResource(
                R.string.detector_copy_subtitle_lsposed_counts_with_policy,
                managers,
                modules,
                native,
                policy.toInt(),
            )
        }
    }
    return null
}

@Composable
internal fun localizeVirtualizationSummary(text: String): String? {
    virtualizationSubtitle.matchEntire(text)?.let { match ->
        val parts = mutableListOf(
            stringResource(
                R.string.detector_copy_subtitle_virtualization,
                match.groupValues[1].toInt(),
                match.groupValues[2].toInt(),
                match.groupValues[3].toInt(),
            ),
        )
        match.groupValues[4].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_dex, it.toInt())
        }
        match.groupValues[5].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_uid, it.toInt())
        }
        match.groupValues[6].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_traps, it.toInt())
        }
        match.groupValues[7].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_host_apps, it.toInt())
        }
        return parts.joinToString(" · ")
    }
    return null
}

@Composable
internal fun localizeMemoryNativeSummary(text: String): String? {
    memoryNativeSubtitle.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_subtitle_memory_native, count)
    }
    return null
}

@Composable
internal fun localizeSignalCount(text: String): String? {
    signalCount.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return@let
        val noun = localizeSignalNoun(match.groupValues[2]) ?: return@let
        return if (match.groupValues[3].isNotEmpty()) {
            pluralStringResource(R.plurals.detector_copy_signal_review, count, count, noun)
        } else {
            pluralStringResource(R.plurals.detector_copy_signal_count, count, count, noun)
        }
    }
    return null
}

@Composable
internal fun localizeZygiskSummary(text: String): String? {
    zygiskSubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_zygisk_subtitle,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    return null
}

@Composable
private fun localizeSignalNoun(noun: String): String? = when (noun) {
    "property" -> stringResource(R.string.detector_copy_signal_noun_property)
    "native" -> stringResource(R.string.detector_copy_signal_noun_native)
    "mount" -> stringResource(R.string.detector_copy_signal_noun_mount)
    "critical mount" -> stringResource(R.string.detector_copy_signal_noun_critical_mount)
    "startup" -> stringResource(R.string.detector_copy_signal_noun_startup)
    "critical startup" -> stringResource(R.string.detector_copy_signal_noun_critical_startup)
    "DRM consistency" -> stringResource(R.string.detector_copy_signal_noun_drm_consistency)
    "boot state" -> stringResource(R.string.detector_copy_signal_noun_boot_state)
    "critical boot integrity" -> stringResource(R.string.detector_copy_signal_noun_critical_boot_integrity)
    "high-risk property or coherence" -> stringResource(R.string.detector_copy_signal_noun_high_risk_property_coherence)
    "suspicious kernel" -> stringResource(R.string.detector_copy_signal_noun_suspicious_kernel)
    "high-risk LSPosed" -> stringResource(R.string.detector_copy_signal_noun_high_risk_lsposed)
    "LSPosed residue" -> stringResource(R.string.detector_copy_signal_noun_lsposed_residue)
    "direct virtualization" -> stringResource(R.string.detector_copy_signal_noun_direct_virtualization)
    "virtualization" -> stringResource(R.string.detector_copy_signal_noun_virtualization)
    "runtime root" -> stringResource(R.string.detector_copy_signal_noun_runtime_root)
    "high-risk memory" -> stringResource(R.string.detector_copy_signal_noun_high_risk_memory)
    "high-confidence residue" -> stringResource(R.string.detector_copy_signal_noun_high_confidence_residue)
    "strong" -> stringResource(R.string.detector_copy_signal_noun_strong)
    "direct runtime" -> stringResource(R.string.detector_copy_signal_noun_direct_runtime)
    "modification" -> stringResource(R.string.detector_copy_signal_noun_modification)
    "signal" -> stringResource(R.string.detector_copy_signal_noun_generic)
    else -> null
}
