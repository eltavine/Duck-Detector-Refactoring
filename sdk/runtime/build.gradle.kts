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

import com.eltavine.duckdetector.buildlogic.DETECTOR_LAYER
import com.eltavine.duckdetector.buildlogic.DUCK_DETECTOR_VERSION_CODE_BASE
import com.eltavine.duckdetector.buildlogic.GitCommitCountValueSource
import com.eltavine.duckdetector.buildlogic.GitShortHashValueSource
import com.eltavine.duckdetector.buildlogic.detectorModules

plugins {
    id("duckdetector.android.library")
    id("duckdetector.public-api")
    id("duckdetector.contract-values")
}

val preloadBuildRevision = providers.environmentVariable("GITHUB_SHA")
    .map { it.take(12) }
    .orElse(
        providers.of(GitShortHashValueSource::class.java) {
            parameters.repositoryRoot.set(rootDir.absolutePath)
        }
    )
    .orElse("unknown")
val preloadVersionCode = providers.of(GitCommitCountValueSource::class.java) {
    parameters.repositoryRoot.set(rootDir.absolutePath)
}.map { commitCount -> DUCK_DETECTOR_VERSION_CODE_BASE + commitCount }

android {
    namespace = "com.eltavine.duckdetector.sdk"
    buildFeatures {
        // The preload executes before PackageManager metadata is populated in ApplicationInfo.
        buildConfig = true
    }
    defaultConfig {
        buildConfigField("int", "PRELOAD_VERSION_CODE", preloadVersionCode.get().toString())
        buildConfigField("String", "PRELOAD_BUILD_REVISION", "\"${preloadBuildRevision.get()}\"")
    }
}

kotlin {
    explicitApi()
}

dependencies {
    implementation(project(":capability:earlypreload:data"))
    implementation(project(":capability:packageinventory:data"))
    implementation(project(":capability:packageinventory:domain"))
    implementation(project(":capability:selinuxpolicy:data"))
    implementation(project(":core:evidence"))
    api(project(":core:detector"))
    api(project(":core:report"))
    // Every detector unit, discovered from its directory, so the catalog and the AAR can hold all of them.
    detectorModules(DETECTOR_LAYER).forEach { implementation(project(it)) }
    api(libs.kotlinx.coroutines.core)
}
