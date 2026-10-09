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

package com.eltavine.duckdetector.features.heapresidue.data

import android.os.Build
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueRelease

/**
 * Startup argument parsing, the HPROF String encoding, the VMDebug FD path, the pipe flush and the
 * isolated_app pipe policy were audited unchanged from Android 12 to 17 (research/version-support).
 * Newer and pre-release builds run on the runtime checks alone; older releases were not audited.
 */
internal object HeapResidueReleases {
    const val FIRST_AUDITED_API = 31
    const val LAST_AUDITED_API = 37

    /** Null when the probe must not run on [api]. */
    fun classify(api: Int, prerelease: Boolean): HeapResidueRelease? = when {
        api < FIRST_AUDITED_API -> null
        // A developer preview still reports the previous release's SDK_INT; its sources are newer.
        prerelease -> HeapResidueRelease.PRERELEASE
        api <= LAST_AUDITED_API -> HeapResidueRelease.AUDITED
        else -> HeapResidueRelease.NEWER
    }

    /** Production builds report CODENAME "REL" and PREVIEW_SDK_INT 0. */
    fun current(): HeapResidueRelease? = classify(
        Build.VERSION.SDK_INT,
        prerelease = Build.VERSION.CODENAME != "REL" || Build.VERSION.PREVIEW_SDK_INT != 0,
    )
}
