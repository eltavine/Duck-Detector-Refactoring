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
    id("duckdetector.android.library")
    id("duckdetector.android.compose")
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.eltavine.duckdetector.core.navigation"
    // MIUIX Nav 0.9.4's entry<T>() is JVM-21 inline code. Isolate that one source-level
    // requirement here; all regular Duck modules, including :app and the detector SDK, stay 17.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

dependencies {
    api(libs.uihelper)
    api(libs.androidx.ui)
    api(libs.kotlinx.serialization.core)
    api(libs.miuix.nav)
}
