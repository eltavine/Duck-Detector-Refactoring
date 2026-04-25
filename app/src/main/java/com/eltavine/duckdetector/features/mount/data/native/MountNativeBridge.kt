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

package com.eltavine.duckdetector.features.mount.data.native

open class MountNativeBridge {

    open fun collectSnapshot(): MountNativeSnapshot {
        return runCatching {
            parse(nativeCollectSnapshot())
        }.getOrDefault(MountNativeSnapshot())
    }

    internal fun parse(raw: String): MountNativeSnapshot {
        if (raw.isBlank()) {
            return MountNativeSnapshot()
        }

        var snapshot = MountNativeSnapshot()
        val findings = mutableListOf<MountNativeFinding>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("FINDING=") -> {
                        val parts = line.removePrefix("FINDING=").split('\t')
                        if (parts.size >= 5) {
                            findings += MountNativeFinding(
                                group = parts[0],
                                severity = parts[1],
                                label = parts[2],
                                value = parts[3],
                                detail = parts[4],
                            )
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = snapshot.applyEntry(key, value)
                    }
                }
            }

        return snapshot.copy(findings = findings)
    }

    private fun MountNativeSnapshot.applyEntry(
        key: String,
        value: String,
    ): MountNativeSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "MOUNTS_READABLE" -> copy(mountsReadable = value.asBool())
            "MOUNTINFO_READABLE" -> copy(mountInfoReadable = value.asBool())
            "MAPS_READABLE" -> copy(mapsReadable = value.asBool())
            "FILESYSTEMS_READABLE" -> copy(filesystemsReadable = value.asBool())
            "INIT_NAMESPACE_READABLE" -> copy(initNamespaceReadable = value.asBool())
            "STATX_SUPPORTED" -> copy(statxSupported = value.asBool())
            "PERMISSION_TOTAL" -> copy(permissionTotal = value.toIntOrNull() ?: permissionTotal)
            "PERMISSION_DENIED" -> copy(permissionDenied = value.toIntOrNull() ?: permissionDenied)
            "PERMISSION_ACCESSIBLE" -> copy(
                permissionAccessible = value.toIntOrNull() ?: permissionAccessible
            )

            "MOUNT_ENTRY_COUNT" -> copy(mountEntryCount = value.toIntOrNull() ?: mountEntryCount)
            "MOUNTINFO_ENTRY_COUNT" -> copy(
                mountInfoEntryCount = value.toIntOrNull() ?: mountInfoEntryCount
            )

            "MAP_LINE_COUNT" -> copy(mapLineCount = value.toIntOrNull() ?: mapLineCount)
            "BUSYBOX" -> copy(busyboxDetected = value.asBool())
            "MAGISK_MOUNT" -> copy(magiskMountDetected = value.asBool())
            "ZYGISK_CACHE" -> copy(zygiskCacheDetected = value.asBool())
            "SYSTEM_RW" -> copy(systemRwDetected = value.asBool())
            "OVERLAY_MOUNT" -> copy(overlayMountDetected = value.asBool())
            "NAMESPACE_ANOMALY" -> copy(namespaceAnomalyDetected = value.asBool())
            "DATA_ADB" -> copy(dataAdbDetected = value.asBool())
            "DEBUG_RAMDISK" -> copy(debugRamdiskDetected = value.asBool())
            "HYBRID_MOUNT" -> copy(hybridMountDetected = value.asBool())
            "META_HYBRID_MOUNT" -> copy(metaHybridMountDetected = value.asBool())
            "SUSPICIOUS_TMPFS" -> copy(suspiciousTmpfsDetected = value.asBool())
            "KSU_OVERLAY" -> copy(ksuOverlayDetected = value.asBool())
            "LOOP_DEVICE" -> copy(loopDeviceDetected = value.asBool())
            "DM_VERITY_BYPASS" -> copy(dmVerityBypassDetected = value.asBool())
            "MOUNT_PROPAGATION" -> copy(mountPropagationAnomaly = value.asBool())
            "INCONSISTENT_MOUNT" -> copy(inconsistentMountDetected = value.asBool())
            "MOUNT_ID_LOOPHOLE" -> copy(mountIdLoopholeDetected = value.asBool())
            "PEER_GROUP_LOOPHOLE" -> copy(peerGroupLoopholeDetected = value.asBool())
            "MINOR_DEV_LOOPHOLE" -> copy(minorDevLoopholeDetected = value.asBool())
            "FUTILE_HIDE" -> copy(futileHideDetected = value.asBool())
            "STATX_MNT_ID_MISMATCH" -> copy(statxMntIdMismatch = value.asBool())
            "BIND_MOUNT_DETECTED" -> copy(bindMountDetected = value.asBool())
            "MOUNT_OPTIONS_ANOMALY" -> copy(mountOptionsAnomaly = value.asBool())
            "STATX_MOUNT_ROOT_ANOMALY" -> copy(statxMountRootAnomaly = value.asBool())
            "OVERLAYFS_KERNEL_SUPPORT" -> copy(overlayfsKernelSupport = value.asBool())
            "SYSTEM_FS_TYPE_ANOMALY" -> copy(systemFsTypeAnomaly = value.asBool())
            "TMPFS_SIZE_ANOMALY" -> copy(tmpfsSizeAnomaly = value.asBool())
            else -> this
        }
    }

    private fun String.asBool(): Boolean {
        return this == "1" || equals("true", ignoreCase = true)
    }

    private external fun nativeCollectSnapshot(): String

    companion object {
        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
