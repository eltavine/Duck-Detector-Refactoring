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

import com.eltavine.duckdetector.buildlogic.detectorModules
import com.eltavine.duckdetector.buildlogic.generateDetectorCards

plugins {
    id("duckdetector.android.application")
    id("duckdetector.android.apk-artifacts")
}

android {
    namespace = "com.eltavine.duckdetector"

    defaultConfig {
        applicationId = "com.eltavine.duckdetector"
    }
}

// Every detector's dashboard card, discovered like the ui modules the application depends on.
generateDetectorCards(packageName = "com.eltavine.duckdetector.ui")

dependencies {
    implementation(libs.uihelper)
    implementation(libs.miuix.nav)
    implementation(project(":core:navigation"))
    implementation(project(":core:detector"))
    implementation(project(":core:evidence"))
    implementation(project(":core:scan"))
    implementation(project(":core:ui"))
    implementation(project(":core:designsystem"))
    implementation(project(":feature:dashboard:presentation"))
    implementation(project(":feature:dashboard:ui"))
    implementation(project(":feature:deviceinfo:data"))
    implementation(project(":feature:deviceinfo:domain"))
    implementation(project(":feature:deviceinfo:ui"))
    implementation(project(":feature:settings:presentation"))
    implementation(project(":feature:settings:ui"))
    implementation(project(":feature:update:data"))
    implementation(project(":feature:update:domain"))
    implementation(project(":feature:update:presentation"))
    implementation(project(":feature:update:ui"))
    implementation(project(":sdk:runtime"))
    // Every detector's dashboard card, discovered like the SDK discovers the detectors.
    detectorModules("ui").forEach { implementation(project(it)) }
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.material)
    testImplementation(project(":core:report"))
    testImplementation(project(":feature:deviceinfo:presentation"))
    testImplementation(libs.bundles.test.unit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.ui.tooling)
}
