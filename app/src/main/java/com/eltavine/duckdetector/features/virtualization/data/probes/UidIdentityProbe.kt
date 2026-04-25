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

package com.eltavine.duckdetector.features.virtualization.data.probes

import android.app.Application
import android.content.Context
import android.os.Process
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppsCatalog
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

data class UidIdentityProbeResult(
    val uid: Int = -1,
    val applicationUid: Int = -1,
    val packageName: String = "",
    val processName: String = "",
    val uidName: String = "",
    val packagesForUid: List<String> = emptyList(),
    val hitCount: Int = 0,
    val signals: List<VirtualizationSignal> = emptyList(),
    val hostPackageHit: Boolean = false,
)

open class UidIdentityProbe(
    private val context: Context? = null,
    private val uidProvider: () -> Int = { Process.myUid() },
    private val processNameProvider: () -> String = { Application.getProcessName() },
) {

    open fun probe(): UidIdentityProbeResult {
        val appContext = context?.applicationContext ?: return UidIdentityProbeResult()
        val packageManager = appContext.packageManager
        val uid = runCatching(uidProvider).getOrDefault(-1)
        val applicationUid = runCatching { appContext.applicationInfo.uid }.getOrDefault(-1)
        val packageName = appContext.packageName
        val processName = runCatching(processNameProvider).getOrDefault("")
        val packagesForUid = runCatching {
            packageManager.getPackagesForUid(uid)?.toList().orEmpty()
        }.getOrDefault(emptyList())
            .map { it.orEmpty() }
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
        val uidName = runCatching { packageManager.getNameForUid(uid).orEmpty() }.getOrDefault("")

        return evaluate(
            uid = uid,
            applicationUid = applicationUid,
            packageName = packageName,
            processName = processName,
            uidName = uidName,
            packagesForUid = packagesForUid,
        )
    }

    internal fun evaluate(
        uid: Int,
        applicationUid: Int,
        packageName: String,
        processName: String,
        uidName: String,
        packagesForUid: List<String>,
    ): UidIdentityProbeResult {
        val signals = mutableListOf<VirtualizationSignal>()
        val hostPackages =
            packagesForUid.filter { VirtualizationHostAppsCatalog.targetByPackage.containsKey(it) }

        if (uid >= 0 && applicationUid >= 0 && uid != applicationUid) {
            signals += VirtualizationSignal(
                id = "virt_uid_app_mismatch",
                label = "Application UID mismatch",
                value = "Danger",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.DANGER,
                detail = "Process.myUid=$uid applicationInfo.uid=$applicationUid",
                detailMonospace = true,
            )
        }

        if (hostPackages.isNotEmpty()) {
            signals += VirtualizationSignal(
                id = "virt_uid_host_package",
                label = "Host package shares UID",
                value = hostPackages.joinToString(separator = ", "),
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.DANGER,
                detail = buildString {
                    append("packagesForUid(")
                    append(uid)
                    append(")=\n")
                    append(packagesForUid.joinToString(separator = "\n"))
                },
                detailMonospace = true,
            )
        }

        if (uid >= 0 && packageName.isNotBlank() && packageName !in packagesForUid) {
            signals += VirtualizationSignal(
                id = "virt_uid_missing_self",
                label = "Current package missing from UID",
                value = packageName,
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.DANGER,
                detail = buildString {
                    append("packagesForUid(")
                    append(uid)
                    append(")=\n")
                    append(packagesForUid.joinToString(separator = "\n").ifBlank { "<empty>" })
                },
                detailMonospace = true,
            )
        }

        if (uid >= 0 && uidName.isBlank()) {
            signals += VirtualizationSignal(
                id = "virt_uid_name_blank",
                label = "UID name unavailable",
                value = "Review",
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = "PackageManager.getNameForUid($uid) returned no stable name.",
                detailMonospace = true,
            )
        }

        if (processName.isNotBlank() && packageName.isNotBlank() && !processName.startsWith(
                packageName
            )
        ) {
            signals += VirtualizationSignal(
                id = "virt_uid_process_name",
                label = "Unexpected process identity",
                value = processName,
                group = VirtualizationSignalGroup.CONSISTENCY,
                severity = VirtualizationSignalSeverity.WARNING,
                detail = "Expected process name to start with $packageName",
                detailMonospace = true,
            )
        }

        return UidIdentityProbeResult(
            uid = uid,
            applicationUid = applicationUid,
            packageName = packageName,
            processName = processName,
            uidName = uidName,
            packagesForUid = packagesForUid,
            hitCount = signals.count {
                it.severity == VirtualizationSignalSeverity.DANGER ||
                        it.severity == VirtualizationSignalSeverity.WARNING
            },
            signals = signals,
            hostPackageHit = hostPackages.isNotEmpty(),
        )
    }
}
