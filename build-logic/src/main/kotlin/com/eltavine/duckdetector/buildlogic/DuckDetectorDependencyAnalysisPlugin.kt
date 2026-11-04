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

import com.autonomousapps.DependencyAnalysisExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.configure

/**
 * Makes `./gradlew buildHealth` fail on any dependency a module declares but does not use, uses
 * without declaring, or declares with the wrong visibility, so dependencies stay minimal.
 *
 * Applied to the root project; each module's convention plugin applies the Dependency Analysis
 * plugin too. It has to come from this build's classpath, because it must share a class loader
 * with the Android and Kotlin plugins.
 */
class DuckDetectorDependencyAnalysisPlugin : Plugin<Project> {
    override fun apply(target: Project) {
        target.pluginManager.apply("com.autonomousapps.dependency-analysis")
        target.extensions.configure<DependencyAnalysisExtension> {
            abi {
                exclusions {
                    // The Compose compiler emits these public holders for composable lambdas; they are
                    // not part of any module's API.
                    excludeClasses(".*\\.ComposableSingletons\\$.*")
                }
            }
            issues {
                all {
                    onAny { severity("fail") }
                    // The boundary policy, not the class usage, decides whether a module is Android.
                    onModuleStructure { severity("ignore") }
                    // Every module gets the same unit test tools from its convention plugin.
                    onUnusedDependencies {
                        exclude("junit:junit", "org.json:json", "org.jetbrains.kotlinx:kotlinx-coroutines-test")
                    }
                    // Dependency Analysis 3.20.1 sometimes treats a test-only coroutine helper
                    // as a production API/implementation dependency. The test classpath must not
                    // be promoted into production just to satisfy that advice.
                    onIncorrectConfiguration {
                        exclude("org.jetbrains.kotlinx:kotlinx-coroutines-test")
                    }
                }
                // Compose and lifecycle artifacts are intentionally exposed by these UI modules.
                // The 3.20.1 analyzer can report api -> implementation even when Kotlin public
                // declarations expose their types (including composable and ViewModel APIs).
                // Scope exceptions to the existing public-facing dependencies of each module.
                val intentionallyExportedUiDependencies = mapOf(
                    ":core:designsystem" to listOf("androidx.compose.material3:material3"),
                    ":core:navigation" to listOf("androidx.compose.ui:ui"),
                    ":core:ui" to listOf("androidx.compose.material3:material3"),
                    ":feature:dashboard:ui" to listOf("androidx.compose.material3:material3"),
                    ":feature:deviceinfo:ui" to listOf(
                        "androidx.compose.material3:material3",
                        "androidx.lifecycle:lifecycle-viewmodel-compose",
                    ),
                    ":feature:settings:ui" to listOf("androidx.compose.material3:material3"),
                    ":feature:tee:ui" to listOf(
                        "androidx.compose.material3:material3",
                        "androidx.lifecycle:lifecycle-viewmodel-compose",
                    ),
                    ":feature:update:ui" to listOf("androidx.compose.material3:material3"),
                )
                intentionallyExportedUiDependencies.forEach { (module, dependencies) ->
                    project(module) {
                        onIncorrectConfiguration { exclude(*dependencies.toTypedArray()) }
                    }
                }
                // DetectorId is a value class, so the JVM signatures of Detector erase it, but every
                // Kotlin caller of Detector.id still needs :core:evidence.
                project(":core:detector") {
                    onIncorrectConfiguration { exclude(":core:evidence") }
                }
                // DetectorCatalog.all and DuckDetector.detectors are List<Detector<*, *>>. The plugin
                // reads erased descriptors, so a type used only as a generic argument of a public
                // signature does not count as API to it.
                project(":sdk:runtime") {
                    onIncorrectConfiguration { exclude(":core:detector") }
                }
            }
            structure {
                ignoreKtx(true)
                // Artifacts of one library family that are versioned and published together.
                bundle("compose") { include("^androidx\\.compose\\..*") }
                bundle("coroutines") { include("^org\\.jetbrains\\.kotlinx:kotlinx-coroutines-.*") }
                bundle("lifecycle") { include("^androidx\\.lifecycle:.*") }
                bundle("datastore") { include("^androidx\\.datastore:.*") }
                bundle("android-test") {
                    include("^androidx\\.test.*")
                    includeDependency("junit:junit")
                }
                bundle("aboutlibraries") { includeGroup("com.mikepenz") }
            }
        }
    }
}
