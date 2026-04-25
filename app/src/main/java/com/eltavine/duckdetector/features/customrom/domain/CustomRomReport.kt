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

package com.eltavine.duckdetector.features.customrom.domain

enum class CustomRomStage {
    LOADING,
    READY,
    FAILED,
}

enum class CustomRomPackageVisibility {
    FULL,
    RESTRICTED,
}

enum class CustomRomMethodOutcome {
    CLEAN,
    DETECTED,
    SUPPORT,
}

data class CustomRomFinding(
    val romName: String,
    val signal: String,
    val detail: String,
)

data class CustomRomMethodResult(
    val label: String,
    val summary: String,
    val outcome: CustomRomMethodOutcome,
    val detail: String? = null,
)

data class CustomRomReport(
    val stage: CustomRomStage,
    val packageVisibility: CustomRomPackageVisibility,
    val detectedRoms: List<String>,
    val propertyFindings: List<CustomRomFinding>,
    val buildFindings: List<CustomRomFinding>,
    val packageFindings: List<CustomRomFinding>,
    val serviceFindings: List<CustomRomFinding>,
    val reflectionFindings: List<CustomRomFinding>,
    val platformFileFindings: List<CustomRomFinding>,
    val resourceInjectionFindings: List<CustomRomFinding>,
    val recoveryScripts: List<String>,
    val policyFindings: List<CustomRomFinding>,
    val overlayFindings: List<CustomRomFinding>,
    val nativeAvailable: Boolean,
    val checkedPropertyCount: Int,
    val checkedBuildFieldCount: Int,
    val checkedPackageCount: Int,
    val checkedServiceCount: Int,
    val listedServiceCount: Int,
    val methods: List<CustomRomMethodResult>,
    val errorMessage: String? = null,
) {
    val buildSignalCount: Int
        get() = propertyFindings.size + buildFindings.size

    val runtimeSignalCount: Int
        get() = packageFindings.size + serviceFindings.size + reflectionFindings.size

    val nativeSignalCount: Int
        get() = platformFileFindings.size + resourceInjectionFindings.size + recoveryScripts.size + policyFindings.size + overlayFindings.size

    val totalFindings: Int
        get() = buildSignalCount + runtimeSignalCount + nativeSignalCount

    val hasIndicators: Boolean
        get() = totalFindings > 0

    companion object {
        fun loading(): CustomRomReport {
            return CustomRomReport(
                stage = CustomRomStage.LOADING,
                packageVisibility = CustomRomPackageVisibility.RESTRICTED,
                detectedRoms = emptyList(),
                propertyFindings = emptyList(),
                buildFindings = emptyList(),
                packageFindings = emptyList(),
                serviceFindings = emptyList(),
                reflectionFindings = emptyList(),
                platformFileFindings = emptyList(),
                resourceInjectionFindings = emptyList(),
                recoveryScripts = emptyList(),
                policyFindings = emptyList(),
                overlayFindings = emptyList(),
                nativeAvailable = true,
                checkedPropertyCount = 0,
                checkedBuildFieldCount = 0,
                checkedPackageCount = 0,
                checkedServiceCount = 0,
                listedServiceCount = 0,
                methods = emptyList(),
            )
        }

        fun failed(message: String): CustomRomReport {
            return CustomRomReport(
                stage = CustomRomStage.FAILED,
                packageVisibility = CustomRomPackageVisibility.RESTRICTED,
                detectedRoms = emptyList(),
                propertyFindings = emptyList(),
                buildFindings = emptyList(),
                packageFindings = emptyList(),
                serviceFindings = emptyList(),
                reflectionFindings = emptyList(),
                platformFileFindings = emptyList(),
                resourceInjectionFindings = emptyList(),
                recoveryScripts = emptyList(),
                policyFindings = emptyList(),
                overlayFindings = emptyList(),
                nativeAvailable = false,
                checkedPropertyCount = 0,
                checkedBuildFieldCount = 0,
                checkedPackageCount = 0,
                checkedServiceCount = 0,
                listedServiceCount = 0,
                methods = emptyList(),
                errorMessage = message,
            )
        }
    }
}
