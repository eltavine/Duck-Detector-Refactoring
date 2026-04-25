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
                appendLine("FILES_DIR=${appContext.filesDir.absolutePath.encodeValue()}")
                appendLine("CACHE_DIR=${appContext.cacheDir.absolutePath.encodeValue()}")
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
