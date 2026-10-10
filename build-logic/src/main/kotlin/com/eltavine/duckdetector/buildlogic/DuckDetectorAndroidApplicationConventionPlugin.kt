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

import com.android.build.api.dsl.ApplicationExtension
import com.eltavine.duckdetector.buildlogic.assets.registerGeneratedAssets
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

private const val VERSION_CODE_BASE = 300
private const val isAlphaVersion = false

class DuckDetectorAndroidApplicationConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        pluginManager.apply("com.android.application")
        pluginManager.apply("org.jetbrains.kotlin.plugin.compose")
        pluginManager.apply("duckdetector.module-boundaries")
        pluginManager.apply("com.autonomousapps.dependency-analysis")
        registerUnitTestLifecycle("testDebugUnitTest")

        val buildHash = providers.environmentVariable("GITHUB_SHA")
            .map { it.take(12) }
            .orElse(
                providers.of(GitShortHashValueSource::class.java) {
                    parameters.repositoryRoot.set(rootDir.absolutePath)
                }
            )
            .orElse("unknown")
        val buildTimeUtc = providers.gradleProperty("duckdetector.buildTimeUtc")
            .orElse(providers.environmentVariable("BUILD_TIME_UTC"))
            .orElse(
                providers.of(GitCommitTimestampValueSource::class.java) {
                    parameters.repositoryRoot.set(rootDir.absolutePath)
                }
            )
            .orElse("unknown")
        val versionCode = providers.of(GitCommitCountValueSource::class.java) {
            parameters.repositoryRoot.set(rootDir.absolutePath)
        }.map { commitCount ->
            VERSION_CODE_BASE + commitCount
        }
        val appVersion = appVersion(buildHash)

        val releaseKeystorePath = providers.environmentVariable("ANDROID_KEYSTORE_PATH")
        val releaseStorePassword = providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD")
        val releaseKeyAlias = providers.environmentVariable("ANDROID_KEY_ALIAS")
        val releaseKeyPassword = providers.environmentVariable("ANDROID_KEY_PASSWORD")
        val hasReleaseSigning = providers.provider {
            listOf(
                releaseKeystorePath.orNull,
                releaseStorePassword.orNull,
                releaseKeyAlias.orNull,
                releaseKeyPassword.orNull,
            ).all { !it.isNullOrBlank() }
        }

        extensions.configure<ApplicationExtension> {
            configureAndroidCommon(this)
            // The composition root is the single lint entry point, so it must analyse every module it
            // depends on; otherwise code moved out of :app silently leaves lint coverage.
            lint.checkDependencies = true

            defaultConfig {
                targetSdk = requiredIntGradleProperty("duckdetector.android.targetSdk")
                this.versionCode = versionCode.get()
                this.versionName = appVersion.versionName.get()
                buildConfigField("String", "BUILD_TIME_UTC", "\"${buildTimeUtc.get()}\"")
                buildConfigField("String", "BUILD_HASH", "\"${buildHash.get()}\"")
                buildConfigField("String", "BUILD_CHANNEL", "\"${appVersion.channel.get().id}\"")
                buildConfigField("boolean", "isAlphaVersion", isAlphaVersion.toString())
            }

            signingConfigs {
                if (hasReleaseSigning.get()) {
                    create("ciRelease") {
                        storeFile = file(requireNotNull(releaseKeystorePath.orNull))
                        storePassword = releaseStorePassword.orNull
                        keyAlias = releaseKeyAlias.orNull
                        keyPassword = releaseKeyPassword.orNull
                    }
                }
            }

            buildTypes {
                release {
                    isMinifyEnabled = true
                    isShrinkResources = true
                    proguardFiles(
                        getDefaultProguardFile("proguard-android-optimize.txt"),
                        "proguard-rules.pro",
                    )
                    signingConfig = if (hasReleaseSigning.get()) {
                         signingConfigs.getByName("ciRelease")
                    } else {
                         signingConfigs.getByName("debug")
                    }
                }
            }

            buildFeatures {
                compose = true
                buildConfig = true
            }

            packaging {
                resources {
                    excludes += "/META-INF/{AL2.0,LGPL2.1}"
                }
            }
        }

        registerGeneratedAssets()
    }
}
