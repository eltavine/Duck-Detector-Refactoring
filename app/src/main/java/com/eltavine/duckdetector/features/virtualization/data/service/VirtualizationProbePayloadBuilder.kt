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

package com.eltavine.duckdetector.features.virtualization.data.service

import android.content.Context
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.probes.DexPathProbe
import com.eltavine.duckdetector.features.virtualization.data.probes.ProcMountViewScanner
import com.eltavine.duckdetector.features.virtualization.data.probes.UidIdentityProbe

internal object VirtualizationProbePayloadBuilder {

    fun buildSnapshotPayload(
        context: Context,
        profile: VirtualizationRemoteProfile,
        classLoader: ClassLoader?,
        nativeBridge: VirtualizationNativeBridge,
    ): String {
        return runCatching {
            val appContext = context.applicationContext
            val dexPathResult = DexPathProbe(
                context = appContext,
                classLoaderProvider = { classLoader },
            ).probe()
            val uidIdentityResult = UidIdentityProbe(appContext).probe()
            val snapshot = nativeBridge.collectSnapshot()

            buildString {
                appendLine("AVAILABLE=1")
                appendLine("PROFILE=${profile.name}")
                appendLine("NATIVE_AVAILABLE=${if (snapshot.available) 1 else 0}")
                appendLine("UID=${uidIdentityResult.uid}")
                appendLine("PACKAGE_NAME=${appContext.packageName.encodeValue()}")
                appendLine("PROCESS_NAME=${uidIdentityResult.processName.encodeValue()}")
                appendLine("UID_NAME=${uidIdentityResult.uidName.encodeValue()}")
                appendLine(
                    "PACKAGES_FOR_UID=${uidIdentityResult.packagesForUid.encodeList()}",
                )
                appendLine(
                    "CLASS_PATH_ENTRIES=${dexPathResult.classPathEntries.encodeList()}",
                )
                appendLine("SOURCE_DIR=${dexPathResult.sourceDir.encodeValue()}")
                appendLine(
                    "SPLIT_SOURCE_DIRS=${dexPathResult.splitSourceDirs.encodeList()}",
                )
                appendLine(
                    "MOUNT_NAMESPACE_INODE=${snapshot.mountNamespaceInode.encodeValue()}",
                )
                appendLine("APEX_MOUNT_KEY=${snapshot.apexMountKey.encodeValue()}")
                appendLine("SYSTEM_MOUNT_KEY=${snapshot.systemMountKey.encodeValue()}")
                appendLine("VENDOR_MOUNT_KEY=${snapshot.vendorMountKey.encodeValue()}")
                // Isolated services lack normal app-private storage; filesDir/cacheDir can throw
                // ENOENT and erase the payload. Keep storage-only probes out of this branch.
                // isolated service 没有普通 app-private storage，不能让预期 ENOENT 抹掉 mount 证据。
                // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/res/res/values/attrs_manifest.xml
                if (profile != VirtualizationRemoteProfile.ISOLATED) {
                    appendLine("FILES_DIR=${appContext.filesDir.absolutePath.encodeValue()}")
                    appendLine("CACHE_DIR=${appContext.cacheDir.absolutePath.encodeValue()}")
                }
                appendLine("CODE_PATH=${appContext.applicationInfo.sourceDir.encodeValue()}")
                snapshot.findings.forEach { finding ->
                    append("FINDING=")
                    append(finding.group)
                    append('\t')
                    append(finding.severity)
                    append('\t')
                    append(finding.label)
                    append('\t')
                    append(finding.value)
                    append('\t')
                    appendLine(finding.detail.encodeValue())
                }
            }
        }.getOrElse { throwable ->
            buildString {
                appendLine("AVAILABLE=0")
                appendLine("PROFILE=${profile.name}")
                appendLine("NATIVE_AVAILABLE=0")
                appendLine("ERROR=${(throwable.message ?: "Remote snapshot failed.").encodeValue()}")
            }
        }
    }

    fun buildProcMountViewPayload(profile: VirtualizationRemoteProfile): String {
        if (profile != VirtualizationRemoteProfile.ISOLATED) {
            return "AVAILABLE=0\nPROFILE=${profile.name}\nERROR=Isolated profile required.\n"
        }
        val mountView = ProcMountViewScanner().scan()
        return buildString {
            appendLine("AVAILABLE=1")
            appendLine("PROFILE=${profile.name}")
            appendLine("NATIVE_AVAILABLE=0")
            appendLine("PROC_MOUNT_VIEW_AVAILABLE=${if (mountView.available) 1 else 0}")
            appendLine("PROC_MOUNT_VIEW_COUNT=${mountView.distinctViewCount}")
            appendLine("PROC_MOUNT_VIEW_EXPECTED=${mountView.expectedViewCount}")
            appendLine("PROC_MOUNT_VIEW_PIDS=${mountView.scannedPidCount}")
            appendLine("PROC_MOUNT_VIEW_DIVERGENT=${if (mountView.divergent) 1 else 0}")
            appendLine("PROC_MOUNT_VIEW_TOKEN_HIT=${if (mountView.tokenHit) 1 else 0}")
            appendLine("PROC_MOUNT_VIEW_TOKEN_KIND=${mountView.tokenKind.encodeValue()}")
            appendLine("PROC_MOUNT_VIEW_TOKEN_DETAIL=${mountView.tokenHitDetail.encodeValue()}")
            appendLine("PROC_MOUNT_VIEW_DETAIL=${mountView.detail.encodeValue()}")
        }
    }

    private fun String.encodeValue(): String {
        return replace("\n", "\\n")
            .replace("\r", "\\r")
    }

    private fun List<String>.encodeList(): String {
        return distinct()
            .filter { it.isNotBlank() }
            .joinToString(separator = VirtualizationProbeProtocol.LIST_SEPARATOR) {
                it.encodeValue()
            }
    }
}
