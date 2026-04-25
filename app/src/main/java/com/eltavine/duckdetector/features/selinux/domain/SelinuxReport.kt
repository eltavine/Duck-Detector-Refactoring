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

package com.eltavine.duckdetector.features.selinux.domain

enum class SelinuxStage {
    LOADING,
    READY,
    FAILED,
}

enum class SelinuxPolicyWeakness {
    NONE,
    MINOR,
    MODERATE,
    SEVERE,
}

data class SelinuxCheckResult(
    val method: String,
    val status: String,
    val isSecure: Boolean?,
    val permissionDenied: Boolean,
    val details: String? = null,
)

data class SelinuxPolicyAnalysis(
    val policyVersion: Int?,
    val policyVersionOk: Boolean,
    val classCount: Int,
    val classCountOk: Boolean,
    val foundClasses: List<String>,
    val missingClasses: List<String>,
    val dangerousTypesFound: List<String>,
    val permissiveDomains: List<String>,
    val processContext: String?,
    val contextType: String?,
    val weakness: SelinuxPolicyWeakness,
    val details: List<String>,
)

data class SelinuxReport(
    val stage: SelinuxStage,
    val mode: SelinuxMode,
    val resolvedStatusLabel: String,
    val filesystemMounted: Boolean,
    val paradoxDetected: Boolean,
    val methods: List<SelinuxCheckResult>,
    val processContext: String?,
    val contextType: String?,
    val policyAnalysis: SelinuxPolicyAnalysis?,
    val auditIntegrity: SelinuxAuditIntegrityAnalysis?,
    val androidVersion: String,
    val apiLevel: Int,
    val errorMessage: String? = null,
) {
    companion object {
        fun loading(): SelinuxReport {
            return SelinuxReport(
                stage = SelinuxStage.LOADING,
                mode = SelinuxMode.UNKNOWN,
                resolvedStatusLabel = "Scanning",
                filesystemMounted = false,
                paradoxDetected = false,
                methods = emptyList(),
                processContext = null,
                contextType = null,
                policyAnalysis = null,
                auditIntegrity = null,
                androidVersion = "",
                apiLevel = 0,
            )
        }

        fun failed(message: String): SelinuxReport {
            return SelinuxReport(
                stage = SelinuxStage.FAILED,
                mode = SelinuxMode.UNKNOWN,
                resolvedStatusLabel = "Failed",
                filesystemMounted = false,
                paradoxDetected = false,
                methods = emptyList(),
                processContext = null,
                contextType = null,
                policyAnalysis = null,
                auditIntegrity = null,
                androidVersion = "",
                apiLevel = 0,
                errorMessage = message,
            )
        }
    }
}
