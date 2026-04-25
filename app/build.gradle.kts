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
    id("duckdetector.android.application")
    id("duckdetector.android.apk-artifacts")
}

android {
    namespace = "com.eltavine.duckdetector"

    defaultConfig {
        applicationId = "com.eltavine.duckdetector"
        versionCode = 220
        versionName = "26.4.4-alpha"
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.app.runtime)
    implementation(libs.bundles.app.compose)
    implementation(libs.aboutlibraries.compose.m3) {
        exclude(group = "com.github.skydoves", module = "compose-stability-runtime")
    }
    implementation(libs.bundles.app.security)
    testImplementation(libs.bundles.test.unit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.bundles.test.android)
    debugImplementation(libs.androidx.ui.tooling)
}
