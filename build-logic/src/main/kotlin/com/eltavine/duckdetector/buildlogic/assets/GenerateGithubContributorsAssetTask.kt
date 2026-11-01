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

package com.eltavine.duckdetector.buildlogic.assets

import java.io.File
import java.io.IOException
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

internal const val GITHUB_CONTRIBUTORS_ASSET_FILE_NAME = "github_contributors.json"

/** Refreshes the committed contributors asset and avatars from GitHub when asked to. */
abstract class GenerateGithubContributorsAssetTask : DefaultTask() {

    init {
        // CI refreshes once before assembly; subsequent tasks and offline builds reuse the asset.
        // Only an explicit refresh bypasses up-to-date checks and reaches the network.
        outputs.upToDateWhen { !refreshEnabled.get() }
    }

    @get:Input
    abstract val refreshEnabled: Property<Boolean>

    @get:Input
    abstract val endpointUrl: Property<String>

    @get:Internal
    abstract val authToken: Property<String>

    @get:Input
    abstract val maxAttempts: Property<Int>

    @get:Input
    abstract val connectTimeoutMillis: Property<Int>

    @get:Input
    abstract val readTimeoutMillis: Property<Int>

    @get:OutputFile
    abstract val contributorsAssetFile: RegularFileProperty

    @get:OutputDirectory
    abstract val avatarOutputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val contributorsFile = contributorsAssetFile.get().asFile
        contributorsFile.parentFile?.mkdirs()
        val avatarDirectory = avatarOutputDirectory.get().asFile.apply { mkdirs() }

        if (!refreshEnabled.get()) {
            if (!contributorsFile.isFile) {
                contributorsFile.writeText("[]", Charsets.UTF_8)
            }
            logger.lifecycle(
                "GitHub contributors sync skipped; pass " +
                    "-Pduckdetector.githubContributors.refresh=true to refresh the asset."
            )
            return
        }

        runCatching { refresh(contributorsFile, avatarDirectory) }
            .onFailure { failure ->
                logger.warn("GitHub contributors sync failed; falling back to local asset: " + failureReason(failure))
            }
            .getOrThrowUnlessRecoverable()
    }

    private fun refresh(contributorsFile: File, avatarDirectory: File) {
        val http = AssetHttpClient(connectTimeoutMillis.get(), readTimeoutMillis.get())
        val token = authToken.orNull
        val url = endpointUrl.get()
        val attempts = maxAttempts.get().coerceAtLeast(1)
        val recorded = readRecordedMetadata(contributorsFile)
        val outcome = fetchWithRetries(
            attempts = attempts,
            backoffMillis = { attempt -> (2_000L * attempt).coerceAtMost(10_000L) },
            warn = { attempt, reason -> logger.warn("GitHub contributors fetch attempt $attempt/$attempts failed: $reason") },
        ) {
            // GitHub may return 202 with an empty object while statistics are being computed.
            // Reject it as an incomplete feed and retry before falling back to the local snapshot.
            parseGitHubContributors(http.text(url, githubRequestHeaders(url, token)))
        }
        val remote = when (outcome) {
            is FetchOutcome.Fetched -> outcome.value.also {
                logger.lifecycle("Fetched GitHub contributors from $url on attempt ${outcome.attempt}/$attempts.")
            }
            is FetchOutcome.Failed -> throw GradleException(
                "GitHub contributors sync failed after $attempts attempts.",
                outcome.lastFailure,
            )
        }
        writeContributorsAsset(contributorRecords(remote, recorded), contributorsFile, avatarDirectory) { avatarUrl ->
            http.bytes(avatarUrl, githubRequestHeaders(avatarUrl, token))
        }
    }
}

private fun Result<Unit>.getOrThrowUnlessRecoverable() {
    exceptionOrNull()?.let { failure ->
        if (failure is GradleException || failure is IOException) {
            return
        }
        throw failure
    }
}
