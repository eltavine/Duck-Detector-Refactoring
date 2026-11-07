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

package com.eltavine.duckdetector.buildlogic

import org.gradle.api.GradleException

/** The update channel a build is published on, and the one the app follows until the user picks. */
internal enum class BuildChannel(val id: String) {
    STABLE("stable"),
    NIGHTLY("nightly"),
}

/** `git describe` pattern for stable tags; [nightlyVersionName] rejects anything else it matches. */
internal const val STABLE_TAG_GLOB = "v[0-9][0-9].[0-9]*"

// Stable releases use calendar versions: a two-digit year, the month without padding and a patch
// number within that month, as the first alpha (26.3.1-alpha) did.
private val STABLE_VERSION_REGEX = Regex("""(\d{2})\.([1-9]|1[0-2])\.(0|[1-9]\d*)""")
private val DESCRIBE_REGEX = Regex("""v(.+)-(0|[1-9]\d*)-g([0-9a-f]{7,40})""")
private const val NIGHTLY_HASH_LENGTH = 8

internal fun isStableVersionName(versionName: String): Boolean =
    STABLE_VERSION_REGEX.matches(versionName)

internal fun stableVersionName(releaseTag: String): String {
    val versionName = releaseTag.removePrefix("v")
    if (versionName == releaseTag || !isStableVersionName(versionName)) {
        throw GradleException(
            "Release tag $releaseTag is not a stable calendar version such as v26.10.0.",
        )
    }
    return versionName
}

/**
 * [describe] is `git describe --tags --long` of HEAD against [STABLE_TAG_GLOB]. A Nightly build is
 * named after the stable release it follows and the number of commits past it, so
 * `v26.10.0-5-g1a2b3c4d` becomes `26.10.0-nightly.5+1a2b3c4d`. Without a stable tag behind HEAD,
 * as before the first stable release, the build keeps [fallback].
 */
internal fun nightlyVersionName(describe: String?, fallback: String): String {
    val match = describe?.let(DESCRIBE_REGEX::matchEntire) ?: return fallback
    val (stableVersion, distance, hash) = match.destructured
    if (!isStableVersionName(stableVersion)) {
        return fallback
    }
    return "$stableVersion-nightly.$distance+${hash.take(NIGHTLY_HASH_LENGTH)}"
}

/**
 * The version part of the APK file name. A stable version names its commit through its tag, and a
 * name that already carries the commit keeps it once; others get [shortGitHash] appended. SemVer
 * build metadata's `+` becomes `-`, since GitHub renames release assets with special characters.
 */
internal fun apkVersionedName(versionName: String, shortGitHash: String): String {
    val fileSafeName = versionName.replace('+', '-')
    return if (isStableVersionName(versionName) || shortGitHash in versionName) {
        fileSafeName
    } else {
        "$fileSafeName-$shortGitHash"
    }
}
