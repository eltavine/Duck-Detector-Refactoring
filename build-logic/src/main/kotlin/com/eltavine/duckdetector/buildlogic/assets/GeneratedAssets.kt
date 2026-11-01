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

import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.Project
import org.gradle.kotlin.dsl.getByType

/**
 * Registers the tasks that keep the app's committed assets current: the GitHub contributors asset
 * before every build and the TEE revocation snapshot per variant. Each reaches the network only
 * when its refresh property or environment variable is set.
 */
internal fun Project.registerGeneratedAssets() {
    pluginManager.withPlugin("com.android.application") {
        val androidComponents = extensions.getByType<ApplicationAndroidComponentsExtension>()
        val generateGithubContributorsAsset = tasks.register(
            "generateGithubContributorsAsset",
            GenerateGithubContributorsAssetTask::class.java,
        ) {
            refreshEnabled.set(
                providers.gradleProperty("duckdetector.githubContributors.refresh")
                    .map(String::toBoolean)
                    .orElse(
                        providers.environmentVariable("DUCKDETECTOR_GITHUB_CONTRIBUTORS_REFRESH")
                            .map(String::toBoolean)
                    )
                    .orElse(false)
            )
            endpointUrl.set(
                providers.gradleProperty("duckdetector.githubContributors.url")
                    .orElse(GITHUB_CONTRIBUTORS_API_URL)
            )
            authToken.set(
                providers.gradleProperty("duckdetector.githubContributors.token")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN"))
                    .orElse(providers.environmentVariable("GH_TOKEN"))
            )
            maxAttempts.set(
                providers.gradleProperty("duckdetector.githubContributors.maxAttempts")
                    .map(String::toInt)
                    .orElse(6)
            )
            connectTimeoutMillis.set(
                providers.gradleProperty("duckdetector.githubContributors.connectTimeoutMillis")
                    .map(String::toInt)
                    .orElse(5_000)
            )
            readTimeoutMillis.set(
                providers.gradleProperty("duckdetector.githubContributors.readTimeoutMillis")
                    .map(String::toInt)
                    .orElse(10_000)
            )
            contributorsAssetFile.set(
                layout.projectDirectory.file("src/main/assets/$GITHUB_CONTRIBUTORS_ASSET_FILE_NAME")
            )
            avatarOutputDirectory.set(
                layout.projectDirectory.dir("src/main/assets/$GITHUB_CONTRIBUTORS_AVATAR_DIRECTORY")
            )
        }
        tasks.named("preBuild").configure {
            dependsOn(generateGithubContributorsAsset)
        }
        // The asset is written into src/main/assets, so every task that reads the asset sources
        // outside preBuild, such as dependency analysis, has to run after it too.
        tasks.named { it.startsWith("explodeAssetSource") }.configureEach {
            dependsOn(generateGithubContributorsAsset)
        }
        androidComponents.onVariants(androidComponents.selector().all()) { variant ->
            val taskName = variant.computeTaskName("generate", "TeeCrlAsset")
            val generateCrlAsset = tasks.register(
                taskName,
                GenerateTeeCrlAssetTask::class.java,
            ) {
                refreshEnabled.set(
                    providers.gradleProperty("duckdetector.teeCrl.refresh")
                        .map(String::toBoolean)
                        .orElse(
                            providers.environmentVariable("DUCKDETECTOR_TEE_CRL_REFRESH")
                                .map(String::toBoolean)
                        )
                        .orElse(false)
                )
                endpointUrl.set(
                    providers.gradleProperty("duckdetector.teeCrl.url")
                        .orElse(TEE_CRL_STATUS_URL)
                )
                maxAttempts.set(
                    providers.gradleProperty("duckdetector.teeCrl.maxAttempts")
                        .map(String::toInt)
                        .orElse(5)
                )
                connectTimeoutMillis.set(
                    providers.gradleProperty("duckdetector.teeCrl.connectTimeoutMillis")
                        .map(String::toInt)
                        .orElse(5_000)
                )
                readTimeoutMillis.set(
                    providers.gradleProperty("duckdetector.teeCrl.readTimeoutMillis")
                        .map(String::toInt)
                        .orElse(5_000)
                )
                fallbackAsset.set(
                    layout.projectDirectory.file(
                        "src/main/assets/$TEE_CRL_FALLBACK_ASSET_FILE_NAME"
                    )
                )
                outputDirectory.set(
                    layout.buildDirectory.dir("generated/teeCrl/${variant.name}/assets")
                )
            }
            variant.sources.assets?.addGeneratedSourceDirectory(
                generateCrlAsset,
                GenerateTeeCrlAssetTask::outputDirectory,
            )
        }
    }
}
