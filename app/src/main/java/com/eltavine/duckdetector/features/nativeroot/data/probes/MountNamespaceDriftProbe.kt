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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteProfile
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationRemoteSnapshot
import com.eltavine.duckdetector.features.virtualization.data.service.VirtualizationIsolatedProbeManager
import java.io.File

data class MountNamespaceDriftProbeResult(
    val available: Boolean,
    val isolatedProcessAvailable: Boolean,
    val mainNamespaceInode: String,
    val isolatedNamespaceInode: String,
    val mountAnchorDriftCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val signalCount: Int
        get() = findings.count { it.severity != NativeRootFindingSeverity.INFO }
}

internal data class LocalMountNamespaceSnapshot(
    val namespaceInode: String = "",
    val apexMountKey: String = "",
    val systemMountKey: String = "",
    val vendorMountKey: String = "",
) {
    val available: Boolean
        get() = namespaceInode.isNotBlank() ||
                apexMountKey.isNotBlank() ||
                systemMountKey.isNotBlank() ||
                vendorMountKey.isNotBlank()
}

internal data class ParsedMountAnchor(
    val mountId: String,
    val majorMinor: String,
    val root: String,
    val mountPoint: String,
    val fsType: String,
    val source: String,
) {
    val anchorKey: String
        get() = listOf(mountId, majorMinor, root, mountPoint, fsType, source).joinToString("|")

    val semanticKey: String
        get() = listOf(
            normalizeField(majorMinor),
            normalizePath(root),
            normalizePath(mountPoint),
            normalizeField(fsType),
            normalizePath(source),
        ).joinToString("|")

    fun semanticSummary(): String {
        return "dev=$majorMinor root=$root point=$mountPoint fs=$fsType source=$source"
    }

    companion object {
        fun parse(raw: String): ParsedMountAnchor? {
            if (raw.isBlank()) {
                return null
            }
            val parts = raw.split('|', limit = 6)
            if (parts.size != 6) {
                return null
            }
            return ParsedMountAnchor(
                mountId = parts[0].trim(),
                majorMinor = parts[1].trim(),
                root = parts[2].trim(),
                mountPoint = parts[3].trim(),
                fsType = parts[4].trim(),
                source = parts[5].trim(),
            )
        }

        private fun normalizeField(value: String): String {
            return value.trim().lowercase()
        }

        private fun normalizePath(value: String): String {
            val normalized = value.trim()
                .replace('\\', '/')
                .replace(Regex("/+"), "/")
            return if (normalized.length > 1 && normalized.endsWith('/')) {
                normalized.dropLast(1).lowercase()
            } else {
                normalized.lowercase()
            }
        }
    }
}

class MountNamespaceDriftProbe(
    context: Context? = null,
    private val isolatedProbeManager: VirtualizationIsolatedProbeManager =
        VirtualizationIsolatedProbeManager(context?.applicationContext),
) {

    suspend fun run(): MountNamespaceDriftProbeResult {
        val localSnapshot = collectLocalSnapshot()
        val isolatedSnapshot = isolatedProbeManager.collect()
        return evaluate(localSnapshot, isolatedSnapshot)
    }

    internal fun evaluate(
        localSnapshot: LocalMountNamespaceSnapshot,
        isolatedSnapshot: VirtualizationRemoteSnapshot,
    ): MountNamespaceDriftProbeResult {
        if (!localSnapshot.available) {
            return MountNamespaceDriftProbeResult(
                available = false,
                isolatedProcessAvailable = isolatedSnapshot.available,
                mainNamespaceInode = localSnapshot.namespaceInode,
                isolatedNamespaceInode = isolatedSnapshot.mountNamespaceInode,
                mountAnchorDriftCount = 0,
                findings = emptyList(),
                detail = "Could not read the current process mount namespace or anchor mounts.",
            )
        }

        if (
            !isolatedSnapshot.available ||
            isolatedSnapshot.profile != VirtualizationRemoteProfile.ISOLATED
        ) {
            return MountNamespaceDriftProbeResult(
                available = true,
                isolatedProcessAvailable = false,
                mainNamespaceInode = localSnapshot.namespaceInode,
                isolatedNamespaceInode = isolatedSnapshot.mountNamespaceInode,
                mountAnchorDriftCount = 0,
                findings = emptyList(),
                detail = isolatedSnapshot.errorDetail.ifBlank {
                    "The isolated helper process did not return mount namespace data."
                },
            )
        }

        val driftLines = buildList {
            compareSingleMountAnchor(
                "/apex",
                localSnapshot.apexMountKey,
                isolatedSnapshot.apexMountKey
            )
                ?.let(::add)
            compareSingleMountAnchor(
                "/system",
                localSnapshot.systemMountKey,
                isolatedSnapshot.systemMountKey,
            )?.let(::add)
            compareSingleMountAnchor(
                "/vendor",
                localSnapshot.vendorMountKey,
                isolatedSnapshot.vendorMountKey,
            )?.let(::add)
        }
        val comparableAnchorCount = listOf(
            localSnapshot.apexMountKey to isolatedSnapshot.apexMountKey,
            localSnapshot.systemMountKey to isolatedSnapshot.systemMountKey,
            localSnapshot.vendorMountKey to isolatedSnapshot.vendorMountKey,
        ).count { (mainRaw, otherRaw) -> hasComparableMountAnchors(mainRaw, otherRaw) }
        val namespaceDrift = localSnapshot.namespaceInode.isNotBlank() &&
                isolatedSnapshot.mountNamespaceInode.isNotBlank() &&
                localSnapshot.namespaceInode != isolatedSnapshot.mountNamespaceInode

        val findings = buildList {
            if (driftLines.isNotEmpty()) {
                add(
                    NativeRootFinding(
                        id = "mount_anchor_drift_isolated",
                        label = "Isolated mount anchor drift",
                        value = "${driftLines.size} anchor(s)",
                        detail = driftLines.joinToString(separator = "\n"),
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    ),
                )
            } else if (namespaceDrift && comparableAnchorCount == 0) {
                add(
                    NativeRootFinding(
                        id = "mount_namespace_drift_isolated",
                        label = "Isolated mount namespace drift",
                        value = "Review",
                        detail = "mnt namespace main=${localSnapshot.namespaceInode} isolated=${isolatedSnapshot.mountNamespaceInode}",
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    ),
                )
            }
        }

        return MountNamespaceDriftProbeResult(
            available = true,
            isolatedProcessAvailable = true,
            mainNamespaceInode = localSnapshot.namespaceInode,
            isolatedNamespaceInode = isolatedSnapshot.mountNamespaceInode,
            mountAnchorDriftCount = driftLines.size,
            findings = findings,
            detail = buildString {
                append("mainNamespace=")
                append(localSnapshot.namespaceInode.ifBlank { "<missing>" })
                append("\nisolatedNamespace=")
                append(isolatedSnapshot.mountNamespaceInode.ifBlank { "<missing>" })
                append("\nCompared /apex, /system, and /vendor anchor mounts between the main app process and an isolated helper process.")
                if (driftLines.isNotEmpty()) {
                    append("\n")
                    append(driftLines.joinToString(separator = "\n"))
                } else if (namespaceDrift && comparableAnchorCount == 0) {
                    append("\nOnly mount namespace inode drift was comparable.")
                } else if (comparableAnchorCount > 0) {
                    append("\nSemantic anchor mounts matched.")
                }
            },
        )
    }

    internal fun collectLocalSnapshot(): LocalMountNamespaceSnapshot {
        val namespaceInode = runCatching { Os.readlink(MOUNT_NAMESPACE_PATH) }
            .recoverCatching { error ->
                if (error is ErrnoException) {
                    ""
                } else {
                    throw error
                }
            }
            .getOrDefault("")

        val anchors = linkedMapOf(
            "/apex" to "",
            "/system" to "",
            "/vendor" to "",
        )

        runCatching {
            File(MOUNTINFO_PATH).useLines { lines ->
                lines.forEach { line ->
                    val entry = parseMountInfoLine(line) ?: return@forEach
                    if (entry.mountPoint in anchors && anchors[entry.mountPoint].isNullOrBlank()) {
                        anchors[entry.mountPoint] = entry.anchorKey
                    }
                }
            }
        }

        return LocalMountNamespaceSnapshot(
            namespaceInode = namespaceInode,
            apexMountKey = anchors["/apex"].orEmpty(),
            systemMountKey = anchors["/system"].orEmpty(),
            vendorMountKey = anchors["/vendor"].orEmpty(),
        )
    }

    internal fun parseMountInfoLine(line: String): ParsedMountAnchor? {
        val separator = line.indexOf(" - ")
        if (separator < 0) {
            return null
        }

        val left = line.substring(0, separator).trim().split(Regex("\\s+"))
        val right = line.substring(separator + 3).trim().split(Regex("\\s+"))
        if (left.size < 5 || right.size < 2) {
            return null
        }

        return ParsedMountAnchor(
            mountId = left[0],
            majorMinor = left[2],
            root = left[3],
            mountPoint = left[4],
            fsType = right[0],
            source = right[1],
        )
    }

    private fun compareSingleMountAnchor(
        label: String,
        mainRaw: String,
        otherRaw: String,
    ): String? {
        if (mainRaw.isBlank() && otherRaw.isBlank()) {
            return null
        }
        if (mainRaw.isBlank() || otherRaw.isBlank()) {
            return "$label main=${mainRaw.ifBlank { "<missing>" }} isolated=${otherRaw.ifBlank { "<missing>" }}"
        }

        val mainAnchor = ParsedMountAnchor.parse(mainRaw) ?: return null
        val otherAnchor = ParsedMountAnchor.parse(otherRaw) ?: return null
        if (mainAnchor.semanticKey == otherAnchor.semanticKey) {
            return null
        }
        return "$label main=${mainAnchor.semanticSummary()} isolated=${otherAnchor.semanticSummary()}"
    }

    private fun hasComparableMountAnchors(
        mainRaw: String,
        otherRaw: String,
    ): Boolean {
        return ParsedMountAnchor.parse(mainRaw) != null && ParsedMountAnchor.parse(otherRaw) != null
    }

    private companion object {
        private const val MOUNTINFO_PATH = "/proc/self/mountinfo"
        private const val MOUNT_NAMESPACE_PATH = "/proc/self/ns/mnt"
    }
}
