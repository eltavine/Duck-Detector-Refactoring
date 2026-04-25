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
    implementation(libs.kotlin.gradle.plugin)
}

gradlePlugin {
    plugins {
        register("duckDetectorAndroidApplication") {
            id = "duckdetector.android.application"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorAndroidApplicationConventionPlugin"
        }
        register("duckDetectorAndroidApkArtifacts") {
            id = "duckdetector.android.apk-artifacts"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorApkArtifactsConventionPlugin"
        }
    }
}
