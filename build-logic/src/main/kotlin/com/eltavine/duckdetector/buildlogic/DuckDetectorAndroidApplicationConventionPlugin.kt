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

import com.android.build.api.dsl.ApplicationExtension
import org.gradle.api.JavaVersion
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinAndroidProjectExtension

private const val VERSION_CODE_BASE = 300
private const val VERSION_NAME_ZONE_ID = "Asia/Singapore"
private const val isAlphaVersion = true

class DuckDetectorAndroidApplicationConventionPlugin : Plugin<Project> {
    override fun apply(target: Project) = with(target) {
        pluginManager.apply("com.android.application")
        pluginManager.apply("org.jetbrains.kotlin.plugin.compose")

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
        val versionNameDate = providers.of(CurrentDateVersionNameValueSource::class.java) {
            parameters.zoneId.set(VERSION_NAME_ZONE_ID)
        }
        val versionName = providers.provider {
            "${versionNameDate.get()}-${buildHash.get()}"
        }

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

        val lintBaseline = layout.projectDirectory.file("lint-baseline.xml").asFile

        extensions.configure<ApplicationExtension> {
            compileSdk = requiredIntGradleProperty("duckdetector.android.compileSdk")
            compileSdkMinor = requiredIntGradleProperty("duckdetector.android.compileSdkMinor")
            ndkVersion = requiredGradleProperty("duckdetector.android.ndk")
            buildToolsVersion = requiredGradleProperty("duckdetector.android.buildTools")

            defaultConfig {
                minSdk = requiredIntGradleProperty("duckdetector.android.minSdk")
                targetSdk = requiredIntGradleProperty("duckdetector.android.targetSdk")
                this.versionCode = versionCode.get()
                this.versionName = versionName.get()
                testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
                buildConfigField("String", "BUILD_TIME_UTC", "\"${buildTimeUtc.get()}\"")
                buildConfigField("String", "BUILD_HASH", "\"${buildHash.get()}\"")
                buildConfigField("boolean", "isAlphaVersion", isAlphaVersion.toString())
            }

            if (file("src/main/cpp/CMakeLists.txt").exists()) {
                externalNativeBuild {
                    cmake {
                        path = file("src/main/cpp/CMakeLists.txt")
                        version = requiredGradleProperty("duckdetector.android.cmake")
                    }
                }
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
                    if (hasReleaseSigning.get()) {
                        signingConfig = signingConfigs.getByName("ciRelease")
                    }
                }
            }

            compileOptions {
                sourceCompatibility = JavaVersion.VERSION_17
                targetCompatibility = JavaVersion.VERSION_17
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

            if (lintBaseline.exists()) {
                lint {
                    baseline = lintBaseline
                }
            }
        }

        extensions.configure<KotlinAndroidProjectExtension> {
            compilerOptions {
                jvmTarget.set(JvmTarget.JVM_17)
            }
        }
    }
}
