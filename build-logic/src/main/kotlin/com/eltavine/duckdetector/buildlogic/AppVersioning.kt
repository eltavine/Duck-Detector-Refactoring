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
import org.gradle.api.Project
import org.gradle.api.provider.Provider

private const val VERSION_NAME_ZONE_ID = "Asia/Singapore"
private const val RELEASE_TAG_PROPERTY = "duckdetector.releaseTag"

internal class AppVersion(
    val channel: Provider<BuildChannel>,
    val versionName: Provider<String>,
)

/**
 * A build is Stable only when the release workflow names its tag through [RELEASE_TAG_PROPERTY];
 * every other build, local ones included, is a Nightly build of the commit it was made from.
 */
internal fun Project.appVersion(buildHash: Provider<String>): AppVersion {
    val releaseTag = providers.gradleProperty(RELEASE_TAG_PROPERTY)
        .map(String::trim)
        .filter(String::isNotEmpty)
    val channel = releaseTag.map { BuildChannel.STABLE }.orElse(BuildChannel.NIGHTLY)
    val describe = providers.of(GitStableDescribeValueSource::class.java) {
        parameters.repositoryRoot.set(rootDir.absolutePath)
    }
    val versionNameDate = providers.of(CurrentDateVersionNameValueSource::class.java) {
        parameters.zoneId.set(VERSION_NAME_ZONE_ID)
    }
    val versionName = providers.provider {
        val tag = releaseTag.orNull
        if (tag != null) {
            val stableName = stableVersionName(tag)
            requireTagAtHead(tag)
            stableName
        } else {
            nightlyVersionName(
                describe = describe.get(),
                fallback = "${versionNameDate.get()}-${buildHash.get()}",
            )
        }
    }
    return AppVersion(channel = channel, versionName = versionName)
}

// The versionCode counts the commits behind HEAD, so a tag that names another commit would label
// this build with a version it is not.
private fun Project.requireTagAtHead(tag: String) {
    fun commitOf(revision: String): String = providers.of(GitRevisionCommitValueSource::class.java) {
        parameters.repositoryRoot.set(rootDir.absolutePath)
        parameters.revision.set(revision)
    }.get()

    val tagCommit = commitOf("refs/tags/$tag")
    val headCommit = commitOf("HEAD")
    if (!FULL_SHA_REGEX.matches(tagCommit) || tagCommit != headCommit) {
        throw GradleException(
            "Release tag $tag resolves to $tagCommit, but the build is on $headCommit. " +
                "Stable builds must be made from the tagged commit.",
        )
    }
}

private val FULL_SHA_REGEX = Regex("[0-9a-f]{40}")
