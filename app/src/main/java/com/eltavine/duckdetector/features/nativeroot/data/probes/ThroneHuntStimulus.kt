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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import android.os.Build

data class ThroneHuntStimulusOutcome(
    val applied: Boolean,
    val detail: String,
)

// Zero-permission packages.list rewrite. PackageManager.setMimeGroup is hardcoded client-side to
// the caller's own package (ApplicationPackageManager passes mContext.getPackageName()), and the
// server only enforces isSameApp(), so no permission is required. The write is coalesced by
// Settings.scheduleWriteSettings() (10 s), which then lands as a temp file plus rename - exactly
// the FS_CREATE|FS_MOVE sequence KernelSU's pkg_observer reacts to.
object ThroneHuntStimulus {

    internal val MARK_A = setOf("application/x-duckdetector-throne-a")
    internal val MARK_B = setOf("application/x-duckdetector-throne-b")

    // Must match the android:mimeGroup declared by the manifest intent-filter, otherwise
    // setMimeGroup throws IllegalArgumentException("Unknown MIME group ... for package ...").
    const val MIME_GROUP = "duckdetector-throne-hunt"

    // WRITE_SETTINGS_DELAY in PackageManagerService is 10 s, and scheduleWriteSettings() guards
    // with hasMessages() so an already-pending write is never re-armed. The rewrite therefore
    // cannot land later than 10 s after the stimulus, which makes this a hard upper bound rather
    // than a guess; the allowance covers search_manager walking /data/app afterwards.
    const val SETTINGS_WRITE_DELAY_MS = 10_000L
    const val SEARCH_MANAGER_ALLOWANCE_MS = 3_000L
    const val SETTINGS_WRITE_WINDOW_MS = SETTINGS_WRITE_DELAY_MS + SEARCH_MANAGER_ALLOWANCE_MS

    /**
     * Picks a mark that is guaranteed to differ from [current].
     *
     * PackageManagerService short-circuits a mime set identical to the current one and never
     * rewrites packages.list, which would leave the round silently negative. Deriving the new
     * value from the system's own state - instead of from a counter held in this process - also
     * keeps it correct across cold starts: a per-process counter restarts at the same phase every
     * launch, so every session's first round would submit the same value the previous session
     * ended on and produce nothing but false negatives.
     */
    internal fun nextMark(current: Set<String>?): Set<String> = if (current == MARK_A) MARK_B else MARK_A

    fun apply(context: Context): ThroneHuntStimulusOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return ThroneHuntStimulusOutcome(
                applied = false,
                detail = "setMimeGroup/getMimeGroup are API 30+; this device reports API " +
                    Build.VERSION.SDK_INT,
            )
        }

        val manager = context.applicationContext.packageManager
        return runCatching {
            val current = runCatching { manager.getMimeGroup(MIME_GROUP) }.getOrNull()
            val next = nextMark(current)
            manager.setMimeGroup(MIME_GROUP, next)

            // A silent no-op is the one failure this probe cannot afford, because it looks exactly
            // like "no KernelSU". Read the group back and refuse to call the round clean otherwise.
            val confirmed = runCatching { manager.getMimeGroup(MIME_GROUP) }.getOrNull()
            if (confirmed == next) {
                ThroneHuntStimulusOutcome(
                    applied = true,
                    detail = "$MIME_GROUP ${current ?: "(unset)"} -> $next, read back and confirmed",
                )
            } else {
                ThroneHuntStimulusOutcome(
                    applied = false,
                    detail = "$MIME_GROUP read back as $confirmed but expected $next - " +
                        "PackageManagerService short-circuited, packages.list is not being " +
                        "rewritten and this round cannot be trusted",
                )
            }
        }.getOrElse { throwable ->
            ThroneHuntStimulusOutcome(
                applied = false,
                detail = "${throwable.javaClass.simpleName}: ${throwable.message}",
            )
        }
    }
}
