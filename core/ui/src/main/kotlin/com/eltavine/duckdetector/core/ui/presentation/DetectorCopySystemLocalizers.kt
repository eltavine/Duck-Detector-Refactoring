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

private val customRomSubtitleWithModification =
    Regex("""^(\d+) props · (\d+) mod props · (\d+) packages · (\d+) named services$""")

private val customRomSubtitleWithoutModification =
    Regex("""^(\d+) props · mod props unavailable · (\d+) packages · (\d+) named services$""")

private val listedServices = Regex("""^Listed (\d+) services\.$""")

private const val packageHistoryScope =
    "History resets on reboot and may be filtered by package visibility or hiding modules. It cannot establish current installation, running state or concealment."

private val packageHistoryCount = Regex(
    """^(\d+) monitored package\(s\) appeared in visible changes since boot\. Additions, updates and removals share this list; event type and time are not provided\. (.+)$""",
)

private val packageHistorySequence = Regex("""^Returned sequence: (\d+)\.$""")

private val kernelCheckSubtitle = Regex("""^(\d+) keyword families · (\d+) cmdline rules · (native /proc|fallback file reads)$""")

private val mountSubtitle = Regex("""^(\d+) mounts · (\d+) mountinfo · (\d+) map lines$""")

private val kernelZwcBlocked = Regex("""^ZWC and (\d+) tested ignorable codepoints were blocked\.$""")

private val mountAccessibleChecks = Regex("""^Accessible checks: (\d+)/(\d+)\. Permission-denied checks: (\d+)\. Restricted visibility is not evidence of root\.$""")

private val suSubtitleNative = Regex("""^(\d+) su paths · (\d+) adb daemon paths · native /proc scan$""")

private val suSubtitleFallback = Regex("""^(\d+) su paths · (\d+) adb daemon paths · fallback self context$""")

private val selinuxSubtitle = Regex("""^(\d+) local checks( \+ attr/current timing)?( \+ app_zygote AVC counters)?( \+ policy)?( \+ audit integrity \+ side-channel)?$""")

private val locationRiskSyntheticDetail = Regex(
    """^Up to two synthetic objects; no real fix\. Fields: (.+?)\.(.*)$""",
)

private const val unattributedDirectoryActivityPrefix = "Unattributed directory activity; diagnostic only."

@Composable
internal fun localizeLocationRiskSyntheticDetail(text: String): String? {
    locationRiskSyntheticDetail.matchEntire(text)?.let { match ->
        val fields = match.groupValues[1]
        val tail = match.groupValues[2].replace(
            "Public setMock requires API 31; older releases are unsupported.",
            stringResource(R.string.detector_copy_card_locationrisk_setmock),
        )
        return stringResource(R.string.detector_copy_card_locationrisk_synthetic, fields) + tail
    }
    return null
}

@Composable
internal fun localizeSuSummary(text: String): String? {
    suSubtitleNative.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_su_native,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
    }
    suSubtitleFallback.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_su_fallback,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
    }
    return null
}

@Composable
internal fun localizeSelinuxSummary(text: String): String? {
    selinuxSubtitle.matchEntire(text)?.let { match ->
        val parts = mutableListOf(
            stringResource(R.string.detector_copy_subtitle_selinux_base, match.groupValues[1].toInt()),
        )
        if (match.groupValues[2].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_attr_timing)
        }
        if (match.groupValues[3].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_avc_counters)
        }
        if (match.groupValues[4].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_policy)
        }
        if (match.groupValues[5].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_audit)
        }
        return parts.joinToString(" + ")
    }
    return null
}

@Composable
internal fun localizeKernelSummary(text: String): String? {
    kernelCheckSubtitle.matchEntire(text)?.let { match ->
        val keywordCount = match.groupValues[1].toIntOrNull() ?: return text
        val ruleCount = match.groupValues[2].toIntOrNull() ?: return text
        val source = stringResource(
            if (match.groupValues[3] == "native /proc") {
                R.string.detector_copy_value_native_proc
            } else {
                R.string.detector_copy_value_fallback_file_reads
            },
        )
        return stringResource(R.string.detector_copy_subtitle_kernel_check, keywordCount, ruleCount, source)
    }
    return null
}

@Composable
internal fun localizeMountSummary(text: String): String? {
    mountSubtitle.matchEntire(text)?.let { match ->
        val mounts = match.groupValues[1].toIntOrNull() ?: return text
        val mountInfo = match.groupValues[2].toIntOrNull() ?: return text
        val mapLines = match.groupValues[3].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_subtitle_mount, mounts, mountInfo, mapLines)
    }
    kernelZwcBlocked.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_detail_kernel_zwc_blocked, count)
    }
    mountAccessibleChecks.matchEntire(text)?.let { match ->
        val accessible = match.groupValues[1].toIntOrNull() ?: return text
        val total = match.groupValues[2].toIntOrNull() ?: return text
        val denied = match.groupValues[3].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_detail_mount_accessible_checks, accessible, total, denied)
    }

    return null
}

@Composable
internal fun localizePackageHistory(text: String): String? {
    if (text.endsWith(packageHistoryScope)) {
        val observation = text.removeSuffix(packageHistoryScope).trimEnd()
        val localizedObservation = when (observation) {
            "Not collected." -> stringResource(R.string.detector_copy_package_history_not_collected)
            "Permission denied; change history is unavailable." ->
                stringResource(R.string.detector_copy_package_history_permission_denied)
            "Query failed; change history is unavailable." ->
                stringResource(R.string.detector_copy_package_history_query_failed)
            "Invalid response; change history could not be evaluated." ->
                stringResource(R.string.detector_copy_package_history_invalid_response)
            else -> {
                val match = packageHistoryCount.matchEntire(observation) ?: return text
                val count = match.groupValues[1].toIntOrNull() ?: return text
                val tail = match.groupValues[2]
                val suffix = packageHistorySequence.matchEntire(tail)?.let {
                    stringResource(R.string.detector_copy_package_history_sequence, it.groupValues[1])
                } ?: if (tail == "No visible changes or sequence number were returned.") {
                    stringResource(R.string.detector_copy_package_history_no_visible_changes)
                } else {
                    return text
                }
                pluralStringResource(R.plurals.detector_copy_package_history_count, count, count) + " " + suffix
            }
        }
        return localizedObservation + " " + stringResource(R.string.detector_copy_package_history_scope)
    }
    return null
}

@Composable
internal fun localizeUnattributedDirectoryActivity(text: String): String? {
    if (text.startsWith(unattributedDirectoryActivityPrefix)) {
        return stringResource(R.string.detector_copy_detail_diagnostic_nativeroot_unattributed_directory_activity) +
            text.removePrefix(unattributedDirectoryActivityPrefix)
    }
    return null
}

@Composable
internal fun localizeCustomRomSummary(text: String): String? {
    customRomSubtitleWithModification.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_customrom_subtitle_full,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
            match.groupValues[4].toInt(),
        )
    }
    customRomSubtitleWithoutModification.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_customrom_subtitle_no_mod,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    return null
}

@Composable
internal fun localizeListedServices(text: String): String? {
    listedServices.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_detail_listed_services, match.groupValues[1].toInt())
    }
    return null
}
