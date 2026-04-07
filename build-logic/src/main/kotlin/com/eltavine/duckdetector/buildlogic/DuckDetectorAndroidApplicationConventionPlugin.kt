package com.eltavine.duckdetector.buildlogic

import com.android.build.api.dsl.ApplicationExtension
import org.gradle.api.JavaVersion
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinAndroidProjectExtension

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
                testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
                buildConfigField("String", "BUILD_TIME_UTC", "\"${buildTimeUtc.get()}\"")
                buildConfigField("String", "BUILD_HASH", "\"${buildHash.get()}\"")
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
