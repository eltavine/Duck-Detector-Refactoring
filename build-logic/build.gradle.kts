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

plugins {
    `kotlin-dsl`
}

group = "com.eltavine.duckdetector.buildlogic"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    implementation(libs.android.gradle.plugin)
    implementation(libs.android.apksig)
    implementation(libs.json)
    implementation(libs.kotlin.gradle.plugin)
    implementation(libs.dependency.analysis.gradle.plugin)
    implementation(libs.poko.gradle.plugin)
    compileOnly(libs.kotlin.abi.tools.api)
    testImplementation(libs.junit)
}

tasks.test {
    useJUnit()
}

gradlePlugin {
    plugins {
        register("duckDetectorModuleBoundaries") {
            id = "duckdetector.module-boundaries"
            implementationClass = "com.eltavine.duckdetector.buildlogic.boundaries.DuckDetectorModuleBoundariesPlugin"
        }
        register("duckDetectorAndroidApplication") {
            id = "duckdetector.android.application"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorAndroidApplicationConventionPlugin"
        }
        register("duckDetectorAndroidLibrary") {
            id = "duckdetector.android.library"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorAndroidLibraryConventionPlugin"
        }
        register("duckDetectorAndroidCompose") {
            id = "duckdetector.android.compose"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorAndroidComposeConventionPlugin"
        }
        register("duckDetectorJvmLibrary") {
            id = "duckdetector.jvm.library"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorJvmLibraryConventionPlugin"
        }
        register("duckDetectorAndroidApkArtifacts") {
            id = "duckdetector.android.apk-artifacts"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorApkArtifactsConventionPlugin"
        }
        register("duckDetectorDependencyAnalysis") {
            id = "duckdetector.dependency-analysis"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorDependencyAnalysisPlugin"
        }
        register("duckDetectorContractValues") {
            id = "duckdetector.contract-values"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorContractValuesPlugin"
        }
        register("duckDetectorPublicApi") {
            id = "duckdetector.public-api"
            implementationClass = "com.eltavine.duckdetector.buildlogic.api.DuckDetectorPublicApiPlugin"
        }
        register("duckDetectorSdkDistribution") {
            id = "duckdetector.sdk.distribution"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorSdkDistributionPlugin"
        }
    }
}
