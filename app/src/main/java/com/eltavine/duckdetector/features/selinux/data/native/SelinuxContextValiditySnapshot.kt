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

package com.eltavine.duckdetector.features.selinux.data.native

data class SelinuxContextValiditySnapshot(
    val available: Boolean = false,
    val probeAttempted: Boolean = false,
    val carrierContext: String? = null,
    val carrierMatchesExpected: Boolean = false,
    val carrierControlValid: Boolean? = null,
    val negativeControlRejected: Boolean? = null,
    val fileControlValid: Boolean? = null,
    val fileNegativeControlRejected: Boolean? = null,
    val oracleControlsPassed: Boolean = false,
    val ksuResultsStable: Boolean = false,
    val queryMethod: String = "",
    val ksuDomainValid: Boolean? = null,
    val ksuFileValid: Boolean? = null,
    val bitPair: String? = null,
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
)
