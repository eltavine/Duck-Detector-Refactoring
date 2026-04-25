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

package com.eltavine.duckdetector.buildlogic

import com.android.build.api.artifact.ArtifactTransformationRequest
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.api.variant.BuiltArtifact
import com.android.build.api.variant.VariantOutputConfiguration
import org.gradle.api.DefaultTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.kotlin.dsl.getByType
import java.io.File

class DuckDetectorApkArtifactsConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        pluginManager.withPlugin("com.android.application") {
            val androidComponents = extensions.getByType<ApplicationAndroidComponentsExtension>()

            androidComponents.onVariants(androidComponents.selector().all()) { variant ->
                val taskName = "rename${
                    variant.name.replaceFirstChar { firstChar ->
                        if (firstChar.isLowerCase()) {
                            firstChar.titlecase()
                        } else {
                            firstChar.toString()
                        }
                    }
                }Apk"

                val renameTask = tasks.register(taskName, RenameApkTask::class.java)
                val apkTransformationRequest = variant.artifacts
                    .use(renameTask)
                    .wiredWithDirectories(
                        RenameApkTask::inputApkFolder,
                        RenameApkTask::outputApkFolder,
                    )
                    .toTransformMany(SingleArtifact.APK)

                renameTask.configure {
                    transformationRequest.set(apkTransformationRequest)
                    gitHash.set(
                        providers.environmentVariable("GITHUB_SHA")
                            .map { it.take(8) }
                            .orElse(
                                providers.of(GitShortHashValueSource::class.java) {
                                    parameters.repositoryRoot.set(rootDir.absolutePath)
                                }.map { it.take(8) }
                            )
                            .orElse("unknown")
                    )
                }
            }
        }
    }
}

abstract class RenameApkTask : DefaultTask() {
    @get:InputDirectory
    abstract val inputApkFolder: DirectoryProperty

    @get:OutputDirectory
    abstract val outputApkFolder: DirectoryProperty

    @get:Internal
    abstract val transformationRequest: Property<ArtifactTransformationRequest<RenameApkTask>>

    @get:Input
    abstract val gitHash: Property<String>

    @TaskAction
    fun renameArtifacts() {
        transformationRequest.get().submit(this) { builtArtifact ->
            val inputFile = File(builtArtifact.outputFile)
            val outputFile = outputApkFolder.file(buildApkFileName(builtArtifact)).get().asFile
            outputFile.parentFile.mkdirs()
            inputFile.copyTo(outputFile, overwrite = true)
            outputFile
        }
    }

    private fun buildApkFileName(builtArtifact: BuiltArtifact): String {
        val apkVersionName = builtArtifact.versionName?.takeIf { it.isNotBlank() } ?: "unknown"
        val shortGitHash = gitHash.get().ifBlank { "unknown" }
        return when (builtArtifact.outputType) {
            VariantOutputConfiguration.OutputType.ONE_OF_MANY -> {
                val filterSuffix = builtArtifact.filters.joinToString("-") { filter ->
                    "${filter.filterType.name.lowercase()}-${filter.identifier}"
                }
                "Duck Detector-$apkVersionName-$shortGitHash-$filterSuffix.apk"
            }

            VariantOutputConfiguration.OutputType.SINGLE,
            VariantOutputConfiguration.OutputType.UNIVERSAL -> {
                "Duck Detector-$apkVersionName-$shortGitHash.apk"
            }
        }
    }
}
