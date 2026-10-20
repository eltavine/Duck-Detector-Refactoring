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

package com.eltavine.duckdetector.buildlogic.installer

import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import org.gradle.api.Project
import java.io.File
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.register

private val aapt2ExecutableName: String =
    if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "aapt2.exe" else "aapt2"

/** Keeps the host's application ID, version and selected signing configuration together. */
fun Project.registerInstallerCanaryAssets(template: File, asset: String) {
    val components = extensions.getByType<ApplicationAndroidComponentsExtension>()
    val android = extensions.getByType<ApplicationExtension>()
    val buildTools = android.buildToolsVersion
    components.onVariants { variant ->
        val signing = android.buildTypes.getByName(requireNotNull(variant.buildType)).signingConfig
            ?: android.defaultConfig.signingConfig
            ?: return@onVariants
        val task = tasks.register<GenerateInstallerCanaryTask>("generate${variant.name.replaceFirstChar(Char::uppercaseChar)}InstallerCanary") {
            dependsOn("validateSigning${variant.name.replaceFirstChar(Char::uppercaseChar)}")
            applicationId.set(variant.applicationId)
            manifestTemplate.set(template)
            assetPath.set(asset)
            versionCode.set(variant.outputs.single().versionCode)
            targetSdk.set(requireNotNull(android.defaultConfig.targetSdk))
            aapt2.set(components.sdkComponents.sdkDirectory.map {
                it.file("build-tools/${buildTools}/$aapt2ExecutableName")
            })
            androidJar.set(components.sdkComponents.bootClasspath.map { files -> files.first { it.asFile.name == "android.jar" } })
            keyStoreFile.set(requireNotNull(signing.storeFile))
            keyAlias.set(requireNotNull(signing.keyAlias))
            keyStoreType.set(signing.storeType ?: "JKS")
            storePassword.set(requireNotNull(signing.storePassword))
            keyPassword.set(requireNotNull(signing.keyPassword))
            outputDirectory.set(layout.buildDirectory.dir("generated/installerCanary/${variant.name}/assets"))
        }
        variant.sources.assets?.addGeneratedSourceDirectory(task, GenerateInstallerCanaryTask::outputDirectory)
    }
}
