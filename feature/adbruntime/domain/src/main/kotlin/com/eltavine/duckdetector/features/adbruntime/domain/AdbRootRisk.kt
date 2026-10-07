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

package com.eltavine.duckdetector.features.adbruntime.domain

/**
 * ADB-root risk is separate from runtime contradiction: the property is an AOSP adb-root marker,
 * while init-vs-protocol findings correlate independent runtime surfaces.
 */
enum class AdbRootRisk {
    NONE,
    MARKER,
    ROOT_CAPABLE,
}

fun AdbRuntimeReport.adbRootRisk(): AdbRootRisk {
    if (stage != AdbRuntimeStage.READY) {
        return AdbRootRisk.NONE
    }
    if (samples.any { sample ->
            sample.properties.serviceAdbRoot == "1" &&
                sample.properties.roDebuggable == "1"
        }) {
        return AdbRootRisk.ROOT_CAPABLE
    }
    if (samples.any { sample -> sample.properties.serviceAdbRoot == "1" }) {
        return AdbRootRisk.MARKER
    }
    return AdbRootRisk.NONE
}
