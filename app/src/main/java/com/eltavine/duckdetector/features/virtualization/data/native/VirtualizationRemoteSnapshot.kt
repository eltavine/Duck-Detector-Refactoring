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

package com.eltavine.duckdetector.features.virtualization.data.native

enum class VirtualizationRemoteProfile {
    REGULAR,
    ISOLATED,
}

data class VirtualizationRemoteSnapshot(
    val available: Boolean = false,
    val profile: VirtualizationRemoteProfile = VirtualizationRemoteProfile.REGULAR,
    val nativeAvailable: Boolean = false,
    val uid: Int = -1,
    val packageName: String = "",
    val processName: String = "",
    val uidName: String = "",
    val packagesForUid: List<String> = emptyList(),
    val classPathEntries: List<String> = emptyList(),
    val sourceDir: String = "",
    val splitSourceDirs: List<String> = emptyList(),
    val mountNamespaceInode: String = "",
    val apexMountKey: String = "",
    val systemMountKey: String = "",
    val vendorMountKey: String = "",
    val filesDir: String = "",
    val cacheDir: String = "",
    val codePath: String = "",
    val findings: List<VirtualizationNativeFinding> = emptyList(),
    val errorDetail: String = "",
) {
    val artifactKeys: Set<String>
        get() = findings.mapTo(linkedSetOf()) { "${it.group}:${it.label}:${it.value}" }

    companion object {
        fun parse(raw: String): VirtualizationRemoteSnapshot {
            if (raw.isBlank()) {
                return VirtualizationRemoteSnapshot()
            }

            var available = false
            var profile = VirtualizationRemoteProfile.REGULAR
            var nativeAvailable = false
            var uid = -1
            var packageName = ""
            var processName = ""
            var uidName = ""
            var packagesForUid = emptyList<String>()
            var classPathEntries = emptyList<String>()
            var sourceDir = ""
            var splitSourceDirs = emptyList<String>()
            var mountNamespaceInode = ""
            var apexMountKey = ""
            var systemMountKey = ""
            var vendorMountKey = ""
            var filesDir = ""
            var cacheDir = ""
            var codePath = ""
            var errorDetail = ""
            val findings = mutableListOf<VirtualizationNativeFinding>()

            raw.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .forEach { line ->
                    when {
                        line.startsWith("FINDING=") -> {
                            val parts = line.removePrefix("FINDING=").split('\t')
                            if (parts.size >= 5) {
                                findings += VirtualizationNativeFinding(
                                    group = parts[0],
                                    severity = parts[1],
                                    label = parts[2],
                                    value = parts[3],
                                    detail = parts[4].decodeValue(),
                                )
                            }
                        }

                        line.contains('=') -> {
                            val key = line.substringBefore('=')
                            val value = line.substringAfter('=').decodeValue()
                            when (key) {
                                "AVAILABLE" -> available = value.asBool()
                                "PROFILE" -> {
                                    profile = value.takeIf { it.isNotBlank() }?.let {
                                        runCatching { VirtualizationRemoteProfile.valueOf(it) }
                                            .getOrDefault(VirtualizationRemoteProfile.REGULAR)
                                    } ?: VirtualizationRemoteProfile.REGULAR
                                }

                                "NATIVE_AVAILABLE" -> nativeAvailable = value.asBool()
                                "UID" -> uid = value.toIntOrNull() ?: -1
                                "PACKAGE_NAME" -> packageName = value
                                "PROCESS_NAME" -> processName = value
                                "UID_NAME" -> uidName = value
                                "PACKAGES_FOR_UID" -> packagesForUid = value.decodeList()
                                "CLASS_PATH_ENTRIES" -> classPathEntries = value.decodeList()
                                "SOURCE_DIR" -> sourceDir = value
                                "SPLIT_SOURCE_DIRS" -> splitSourceDirs = value.decodeList()
                                "MOUNT_NAMESPACE_INODE" -> mountNamespaceInode = value
                                "APEX_MOUNT_KEY" -> apexMountKey = value
                                "SYSTEM_MOUNT_KEY" -> systemMountKey = value
                                "VENDOR_MOUNT_KEY" -> vendorMountKey = value
                                "FILES_DIR" -> filesDir = value
                                "CACHE_DIR" -> cacheDir = value
                                "CODE_PATH" -> codePath = value
                                "ERROR" -> errorDetail = value
                            }
                        }
                    }
                }

            return VirtualizationRemoteSnapshot(
                available = available,
                profile = profile,
                nativeAvailable = nativeAvailable,
                uid = uid,
                packageName = packageName,
                processName = processName,
                uidName = uidName,
                packagesForUid = packagesForUid,
                classPathEntries = classPathEntries,
                sourceDir = sourceDir,
                splitSourceDirs = splitSourceDirs,
                mountNamespaceInode = mountNamespaceInode,
                apexMountKey = apexMountKey,
                systemMountKey = systemMountKey,
                vendorMountKey = vendorMountKey,
                filesDir = filesDir,
                cacheDir = cacheDir,
                codePath = codePath,
                findings = findings,
                errorDetail = errorDetail,
            )
        }

        private fun String.decodeValue(): String {
            return replace("\\n", "\n")
                .replace("\\r", "\r")
        }

        private fun String.decodeList(): List<String> {
            if (isBlank()) {
                return emptyList()
            }
            return split(LIST_SEPARATOR)
                .map { it.decodeValue() }
                .filter { it.isNotBlank() }
                .distinct()
        }

        private fun String.asBool(): Boolean {
            return this == "1" || equals("true", ignoreCase = true)
        }

        private const val LIST_SEPARATOR = "\u001f"
    }
}
