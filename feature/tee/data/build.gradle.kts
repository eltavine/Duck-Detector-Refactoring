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
}

android {
    namespace = "com.eltavine.duckdetector.features.tee.data"
}

dependencies {
    api(project(":capability:attestation:data"))
    api(project(":capability:attestation:domain"))
    api(project(":core:detector"))
    api(project(":core:native"))
    implementation(project(":core:platform"))
    api(project(":feature:tee:domain"))
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.hiddenapibypass)
    api(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.annotation)
    implementation(libs.soter.core)
    implementation(libs.json)
    testImplementation(project(":core:evidence"))
}
