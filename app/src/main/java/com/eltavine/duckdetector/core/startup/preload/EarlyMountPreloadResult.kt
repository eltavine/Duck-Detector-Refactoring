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

package com.eltavine.duckdetector.core.startup.preload

import android.content.Intent
import android.os.Bundle

enum class EarlyMountPreloadSource {
    NONE,
    INTENT,
    NATIVE,
}

enum class EarlyMountPreloadSignal(
    val key: String,
    val label: String,
) {
    FUTILE_HIDE("FUTILE_HIDE", "FutileHide"),
    MNT_STRINGS("MNT_STRINGS", "MntStrings"),
    MOUNT_ID_GAP("MOUNT_ID_GAP", "MountIdGap"),
    MINOR_DEV_GAP("MINOR_DEV_GAP", "MinorDevGap"),
    PEER_GROUP_GAP("PEER_GROUP_GAP", "PeerGroupGap"),
}

data class EarlyMountPreloadCapturedExtras(
    val hasRun: Boolean = false,
    val detected: Boolean = false,
    val detectionMethod: String = "",
    val details: String = "",
    val contextValid: Boolean = true,
    val futileHideDetected: Boolean = false,
    val mntStringsDetected: Boolean = false,
    val mountIdGapDetected: Boolean = false,
    val minorDevGapDetected: Boolean = false,
    val peerGroupGapDetected: Boolean = false,
    val nsMntCtimeDeltaNs: Long = 0L,
    val mountInfoCtimeDeltaNs: Long = 0L,
    val mntStringsSource: String = "",
    val mntStringsTarget: String = "",
    val mntStringsFs: String = "",
)

data class EarlyMountPreloadResult(
    val hasRun: Boolean = false,
    val detected: Boolean = false,
    val detectionMethod: String = "",
    val details: String = "",
    val futileHideDetected: Boolean = false,
    val mntStringsDetected: Boolean = false,
    val mountIdGapDetected: Boolean = false,
    val minorDevGapDetected: Boolean = false,
    val peerGroupGapDetected: Boolean = false,
    val nsMntCtimeDeltaNs: Long = 0L,
    val mountInfoCtimeDeltaNs: Long = 0L,
    val mntStringsSource: String = "",
    val mntStringsTarget: String = "",
    val mntStringsFs: String = "",
    val findings: List<String> = emptyList(),
    val isContextValid: Boolean = false,
    val source: EarlyMountPreloadSource = EarlyMountPreloadSource.NONE,
) {
    val available: Boolean
        get() = hasRun

    val activeSignals: List<EarlyMountPreloadSignal>
        get() = buildList {
            if (futileHideDetected) {
                add(EarlyMountPreloadSignal.FUTILE_HIDE)
            }
            if (mntStringsDetected) {
                add(EarlyMountPreloadSignal.MNT_STRINGS)
            }
            if (mountIdGapDetected) {
                add(EarlyMountPreloadSignal.MOUNT_ID_GAP)
            }
            if (minorDevGapDetected) {
                add(EarlyMountPreloadSignal.MINOR_DEV_GAP)
            }
            if (peerGroupGapDetected) {
                add(EarlyMountPreloadSignal.PEER_GROUP_GAP)
            }
        }

    val findingCount: Int
        get() = activeSignals.size

    val hasDangerSignal: Boolean
        get() = futileHideDetected || mntStringsDetected || mountIdGapDetected

    val hasWarningSignal: Boolean
        get() = minorDevGapDetected || peerGroupGapDetected

    fun messagesFor(signal: EarlyMountPreloadSignal): List<String> {
        return findings.mapNotNull { finding ->
            val type = finding.substringBefore('|')
            if (type == signal.key) {
                finding.split('|').getOrNull(1)?.takeIf { it.isNotBlank() }
            } else {
                null
            }
        }
    }

    fun normalize(): EarlyMountPreloadResult {
        val resolvedSignals = activeSignals
        val resolvedDetected = detected || resolvedSignals.isNotEmpty()
        val resolvedMethod = detectionMethod.ifBlank {
            resolvedSignals.joinToString(separator = ", ") { it.label }.ifBlank { "None" }
        }
        val resolvedDetails = details.ifBlank {
            when {
                !hasRun -> "Startup preload did not run."
                resolvedDetected -> "Startup preload detected: $resolvedMethod"
                else -> "Startup preload completed without anomalies."
            }
        }
        val resolvedFindings = if (findings.isNotEmpty()) {
            findings.distinct()
        } else {
            resolvedSignals.map { "${it.key}|${it.label}|${if (it == EarlyMountPreloadSignal.MINOR_DEV_GAP || it == EarlyMountPreloadSignal.PEER_GROUP_GAP) "WARNING" else "DANGER"}" }
        }
        return copy(
            detected = resolvedDetected,
            detectionMethod = resolvedMethod,
            details = resolvedDetails,
            findings = resolvedFindings,
        )
    }

    companion object {
        const val KEY_HAS_RUN = "early_detection_has_run"
        const val KEY_DETECTED = "early_detection_detected"
        const val KEY_DETECTION_METHOD = "early_detection_method"
        const val KEY_DETAILS = "early_detection_details"
        const val KEY_CONTEXT_VALID = "early_preload_context_valid"
        const val KEY_FUTILE_HIDE = "early_futile_hide"
        const val KEY_MNT_STRINGS = "early_mnt_strings"
        const val KEY_MOUNT_ID_GAP = "early_mount_id_gap"
        const val KEY_MINOR_DEV_GAP = "early_minor_dev_gap"
        const val KEY_PEER_GROUP_GAP = "early_peer_group_gap"
        const val KEY_NS_MNT_CTIME_DELTA_NS = "early_ns_mnt_ctime_delta_ns"
        const val KEY_MOUNTINFO_CTIME_DELTA_NS = "early_mountinfo_ctime_delta_ns"
        const val KEY_MNT_STRINGS_SOURCE = "early_mnt_strings_source"
        const val KEY_MNT_STRINGS_TARGET = "early_mnt_strings_target"
        const val KEY_MNT_STRINGS_FS = "early_mnt_strings_fs"

        fun empty(source: EarlyMountPreloadSource = EarlyMountPreloadSource.NONE): EarlyMountPreloadResult {
            return EarlyMountPreloadResult(source = source)
        }

        fun fromIntent(intent: Intent?): EarlyMountPreloadResult {
            return fromBundle(intent?.extras)
        }

        fun fromBundle(bundle: Bundle?): EarlyMountPreloadResult {
            if (bundle == null) {
                return empty()
            }

            val inferredHasRun = bundle.getBoolean(KEY_HAS_RUN, false) ||
                    bundle.containsKey(KEY_DETECTED) ||
                    bundle.containsKey(KEY_DETECTION_METHOD) ||
                    bundle.containsKey(KEY_DETAILS) ||
                    bundle.containsKey(KEY_FUTILE_HIDE) ||
                    bundle.containsKey(KEY_MNT_STRINGS) ||
                    bundle.containsKey(KEY_MOUNT_ID_GAP) ||
                    bundle.containsKey(KEY_MINOR_DEV_GAP) ||
                    bundle.containsKey(KEY_PEER_GROUP_GAP)

            return fromCapturedExtras(
                EarlyMountPreloadCapturedExtras(
                    hasRun = inferredHasRun,
                    detected = bundle.getBoolean(KEY_DETECTED, false),
                    detectionMethod = bundle.getString(KEY_DETECTION_METHOD).orEmpty(),
                    details = bundle.getString(KEY_DETAILS).orEmpty(),
                    contextValid = if (bundle.containsKey(KEY_CONTEXT_VALID)) {
                        bundle.getBoolean(KEY_CONTEXT_VALID, false)
                    } else {
                        inferredHasRun
                    },
                    futileHideDetected = bundle.getBoolean(KEY_FUTILE_HIDE, false),
                    mntStringsDetected = bundle.getBoolean(KEY_MNT_STRINGS, false),
                    mountIdGapDetected = bundle.getBoolean(KEY_MOUNT_ID_GAP, false),
                    minorDevGapDetected = bundle.getBoolean(KEY_MINOR_DEV_GAP, false),
                    peerGroupGapDetected = bundle.getBoolean(KEY_PEER_GROUP_GAP, false),
                    nsMntCtimeDeltaNs = bundle.getLong(KEY_NS_MNT_CTIME_DELTA_NS, 0L),
                    mountInfoCtimeDeltaNs = bundle.getLong(KEY_MOUNTINFO_CTIME_DELTA_NS, 0L),
                    mntStringsSource = bundle.getString(KEY_MNT_STRINGS_SOURCE).orEmpty(),
                    mntStringsTarget = bundle.getString(KEY_MNT_STRINGS_TARGET).orEmpty(),
                    mntStringsFs = bundle.getString(KEY_MNT_STRINGS_FS).orEmpty(),
                ),
            )
        }

        internal fun fromCapturedExtras(extras: EarlyMountPreloadCapturedExtras): EarlyMountPreloadResult {
            return EarlyMountPreloadResult(
                hasRun = extras.hasRun,
                detected = extras.detected,
                detectionMethod = extras.detectionMethod,
                details = extras.details,
                futileHideDetected = extras.futileHideDetected,
                mntStringsDetected = extras.mntStringsDetected,
                mountIdGapDetected = extras.mountIdGapDetected,
                minorDevGapDetected = extras.minorDevGapDetected,
                peerGroupGapDetected = extras.peerGroupGapDetected,
                nsMntCtimeDeltaNs = extras.nsMntCtimeDeltaNs,
                mountInfoCtimeDeltaNs = extras.mountInfoCtimeDeltaNs,
                mntStringsSource = extras.mntStringsSource,
                mntStringsTarget = extras.mntStringsTarget,
                mntStringsFs = extras.mntStringsFs,
                isContextValid = extras.contextValid,
                source = EarlyMountPreloadSource.INTENT,
            ).normalize()
        }

        internal fun fromCapturedValues(values: Map<String, Any?>): EarlyMountPreloadResult {
            val inferredHasRun = values.boolean(KEY_HAS_RUN) ||
                    values.containsKey(KEY_DETECTED) ||
                    values.containsKey(KEY_DETECTION_METHOD) ||
                    values.containsKey(KEY_DETAILS) ||
                    values.containsKey(KEY_FUTILE_HIDE) ||
                    values.containsKey(KEY_MNT_STRINGS) ||
                    values.containsKey(KEY_MOUNT_ID_GAP) ||
                    values.containsKey(KEY_MINOR_DEV_GAP) ||
                    values.containsKey(KEY_PEER_GROUP_GAP)

            return fromCapturedExtras(
                EarlyMountPreloadCapturedExtras(
                    hasRun = inferredHasRun,
                    detected = values.boolean(KEY_DETECTED),
                    detectionMethod = values.string(KEY_DETECTION_METHOD),
                    details = values.string(KEY_DETAILS),
                    contextValid = if (values.containsKey(KEY_CONTEXT_VALID)) {
                        values.boolean(KEY_CONTEXT_VALID)
                    } else {
                        inferredHasRun
                    },
                    futileHideDetected = values.boolean(KEY_FUTILE_HIDE),
                    mntStringsDetected = values.boolean(KEY_MNT_STRINGS),
                    mountIdGapDetected = values.boolean(KEY_MOUNT_ID_GAP),
                    minorDevGapDetected = values.boolean(KEY_MINOR_DEV_GAP),
                    peerGroupGapDetected = values.boolean(KEY_PEER_GROUP_GAP),
                    nsMntCtimeDeltaNs = values.long(KEY_NS_MNT_CTIME_DELTA_NS),
                    mountInfoCtimeDeltaNs = values.long(KEY_MOUNTINFO_CTIME_DELTA_NS),
                    mntStringsSource = values.string(KEY_MNT_STRINGS_SOURCE),
                    mntStringsTarget = values.string(KEY_MNT_STRINGS_TARGET),
                    mntStringsFs = values.string(KEY_MNT_STRINGS_FS),
                ),
            )
        }

        private fun Map<String, Any?>.boolean(key: String): Boolean {
            val value = this[key] ?: return false
            return when (value) {
                is Boolean -> value
                is Number -> value.toInt() != 0
                is String -> value.equals("true", ignoreCase = true) || value == "1"
                else -> false
            }
        }

        private fun Map<String, Any?>.long(key: String): Long {
            val value = this[key] ?: return 0L
            return when (value) {
                is Long -> value
                is Int -> value.toLong()
                is Number -> value.toLong()
                is String -> value.toLongOrNull() ?: 0L
                else -> 0L
            }
        }

        private fun Map<String, Any?>.string(key: String): String {
            return (this[key] as? String).orEmpty()
        }
    }
}
