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
    id("duckdetector.android.library")
    id("duckdetector.android.compose")
}

android {
    namespace = "com.eltavine.duckdetector.features.tee.ui"
}

dependencies {
    implementation(libs.uihelper)
    implementation(project(":capability:attestation:domain"))
    api(project(":core:detector"))
    implementation(project(":core:evidence"))
    implementation(project(":core:report"))
    api(project(":core:scan"))
    api(project(":core:ui"))
    implementation(project(":core:designsystem"))
    implementation(project(":feature:tee:detector"))
    api(project(":feature:tee:domain"))
    api(project(":feature:tee:presentation"))
    api(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.material.icons.extended)
    api(libs.androidx.material3)
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    api(libs.kotlinx.coroutines.android)
}
