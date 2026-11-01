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

package com.eltavine.duckdetector.features.rootmanagers.data.probes.canary

import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryObservation
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryState
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryTarget

/** Exact templates from InstallPackageHelper on the researched Android 13–17 branches. */
internal object InstallerCanaryResultPolicy {
    private const val PERMISSION = InstallerCanaryTarget.PERMISSION
    const val DUPLICATE_PERMISSION = -112
    const val BAD_PERMISSION_GROUP = -127
    private val packageName = Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+")

    fun interpret(
        installerPackage: String,
        missingGroup: String,
        publicStatus: Int,
        legacyStatus: Int?,
        message: String?,
    ): InstallerCanaryObservation {
        if (publicStatus == -1) return InstallerCanaryObservation(InstallerCanaryState.USER_ACTION_REQUIRED)
        if (publicStatus == 0) return InstallerCanaryObservation(
            InstallerCanaryState.UNEXPECTED_SUCCESS, detail = "Unexpected installation success; disable this experiment.",
        )
        val duplicate = "INSTALL_FAILED_DUPLICATE_PERMISSION: Package $installerPackage attempting to redeclare permission $PERMISSION already owned by "
        if (publicStatus == 5 && legacyStatus == DUPLICATE_PERMISSION && message?.startsWith(duplicate) == true) {
            val owner = message.removePrefix(duplicate)
            if (packageName.matches(owner) && owner != installerPackage && owner != "android") {
                return InstallerCanaryObservation(InstallerCanaryState.PERMISSION_OWNER_OBSERVED, owner)
            }
        }
        val missing = "-127: Package $installerPackage attempting to declare permission $PERMISSION in non-existing group $missingGroup"
        // This only establishes that the expected permission conflict was not observed.
        if (publicStatus == 1 && legacyStatus == BAD_PERMISSION_GROUP && message == missing) {
            return InstallerCanaryObservation(InstallerCanaryState.PERMISSION_NOT_OBSERVED)
        }
        return InstallerCanaryObservation(
            InstallerCanaryState.INCONCLUSIVE,
            detail = "Installer returned status $publicStatus, legacy ${legacyStatus ?: "unavailable"}; no verified permission-owner result.",
        )
    }
}
