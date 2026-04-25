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

package com.eltavine.duckdetector.features.lsposed.data.probes

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import java.io.File

data class LSPosedZygotePermissionProbeResult(
    val signals: List<LSPosedSignal>,
    val available: Boolean,
    val auditedGrantCount: Int,
    val mismatchCount: Int,
    val detail: String,
)

class LSPosedZygotePermissionProbe {

    fun run(context: Context): LSPosedZygotePermissionProbeResult {
        val grantedPermissions = loadGrantedPermissions(context)
        val statusContent = readProcStatus()
        return evaluate(grantedPermissions, statusContent)
    }

    internal fun evaluate(
        grantedPermissions: Set<String>,
        statusContent: String?,
    ): LSPosedZygotePermissionProbeResult {
        val auditedRules = AUDIT_RULES.filter { rule -> rule.permission in grantedPermissions }
        if (auditedRules.isEmpty()) {
            return LSPosedZygotePermissionProbeResult(
                signals = emptyList(),
                available = true,
                auditedGrantCount = 0,
                mismatchCount = 0,
                detail = "No currently granted permission in this app maps to the audited zygote-assigned supplemental GID set.",
            )
        }

        val currentGids = parseProcessGroups(statusContent)
            ?: return LSPosedZygotePermissionProbeResult(
                signals = emptyList(),
                available = false,
                auditedGrantCount = auditedRules.size,
                mismatchCount = 0,
                detail = "Could not read /proc/self/status Groups:, so the current process GID set could not be audited.",
            )

        val mismatches = auditedRules.mapNotNull { rule ->
            val missingGids = rule.expectedGids.filterNot { gid -> gid.id in currentGids }
            if (missingGids.isEmpty()) {
                null
            } else {
                PermissionGidMismatch(
                    rule = rule,
                    missingGids = missingGids,
                )
            }
        }

        if (mismatches.isEmpty()) {
            return LSPosedZygotePermissionProbeResult(
                signals = emptyList(),
                available = true,
                auditedGrantCount = auditedRules.size,
                mismatchCount = 0,
                detail = buildString {
                    append("Audited granted permissions against /proc/self/status Groups: ")
                    append(
                        auditedRules.joinToString { rule ->
                            "${rule.shortLabel} -> ${rule.expectedGids.joinToString { gid -> "${gid.label} (${gid.id})" }}"
                        },
                    )
                    append(". Current groups: ")
                    append(currentGids.sorted().joinToString(" "))
                },
            )
        }

        val signals = mismatches.map { mismatch ->
            LSPosedSignal(
                id = "zygote_gid_${mismatch.rule.shortLabel.lowercase()}",
                label = "${mismatch.rule.shortLabel} GID mismatch",
                value = "Restricted",
                group = LSPosedSignalGroup.RUNTIME,
                severity = LSPosedSignalSeverity.DANGER,
                detail = buildString {
                    append("Granted permission ${mismatch.rule.permission} is missing ")
                    append(
                        mismatch.missingGids.joinToString { gid ->
                            "${gid.label} (${gid.id})"
                        },
                    )
                    append(" in /proc/self/status Groups:. This is consistent with zygote permission filtering.")
                    appendLine()
                    append("Current groups: ")
                    append(currentGids.sorted().joinToString(" "))
                },
                detailMonospace = true,
            )
        }

        return LSPosedZygotePermissionProbeResult(
            signals = signals,
            available = true,
            auditedGrantCount = auditedRules.size,
            mismatchCount = mismatches.size,
            detail = buildString {
                append("Granted permission/GID mismatches detected: ")
                appendLine()
                mismatches.forEach { mismatch ->
                    append(" - ")
                    append(mismatch.rule.permission)
                    append(" missing ")
                    append(
                        mismatch.missingGids.joinToString { gid ->
                            "${gid.label} (${gid.id})"
                        },
                    )
                    appendLine()
                }
                append("Current groups: ")
                append(currentGids.sorted().joinToString(" "))
            }.trim(),
        )
    }

    private fun loadGrantedPermissions(context: Context): Set<String> {
        val packageManager = context.packageManager
        val packageInfo = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()),
                )
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_PERMISSIONS,
                )
            }
        }.getOrNull() ?: return emptySet()

        return grantedPermissions(packageInfo)
    }

    private fun readProcStatus(): String? {
        val procStatusFile = File(PROC_STATUS_PATH)
        if (!procStatusFile.exists() || !procStatusFile.canRead()) {
            return null
        }
        return runCatching { procStatusFile.readText() }.getOrNull()
    }

    internal fun grantedPermissions(packageInfo: PackageInfo): Set<String> {
        val permissions = packageInfo.requestedPermissions ?: return emptySet()
        val flags = packageInfo.requestedPermissionsFlags ?: IntArray(0)
        return permissions.mapIndexedNotNull { index, permission ->
            val granted = flags.getOrNull(index)
                ?.and(PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            permission.takeIf { granted }
        }.toSet()
    }

    internal fun parseProcessGroups(statusContent: String?): Set<Int>? {
        val groupsLine = statusContent
            ?.lineSequence()
            ?.firstOrNull { line -> line.startsWith("Groups:") }
            ?: return null
        return groupsLine
            .removePrefix("Groups:")
            .trim()
            .split(Regex("\\s+"))
            .filter { token -> token.isNotBlank() }
            .mapNotNull { token -> token.toIntOrNull() }
            .toSet()
    }

    private data class PermissionGidMismatch(
        val rule: PermissionGidAuditRule,
        val missingGids: List<ExpectedGid>,
    )

    private data class PermissionGidAuditRule(
        val permission: String,
        val shortLabel: String,
        val expectedGids: List<ExpectedGid>,
    )

    private data class ExpectedGid(
        val id: Int,
        val label: String,
    )

    private companion object {
        private const val PROC_STATUS_PATH = "/proc/self/status"

        private val AUDIT_RULES = listOf(
            PermissionGidAuditRule(
                permission = android.Manifest.permission.INTERNET,
                shortLabel = "INTERNET",
                expectedGids = listOf(ExpectedGid(3003, "INET_GID")),
            ),
            PermissionGidAuditRule(
                permission = android.Manifest.permission.BLUETOOTH_ADMIN,
                shortLabel = "BLUETOOTH_ADMIN",
                expectedGids = listOf(ExpectedGid(3001, "NET_BT_ADMIN_GID")),
            ),
            PermissionGidAuditRule(
                permission = android.Manifest.permission.BLUETOOTH,
                shortLabel = "BLUETOOTH",
                expectedGids = listOf(ExpectedGid(3002, "NET_BT_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.NET_TUNNELING",
                shortLabel = "NET_TUNNELING",
                expectedGids = listOf(ExpectedGid(1016, "VPN_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.READ_LOGS",
                shortLabel = "READ_LOGS",
                expectedGids = listOf(ExpectedGid(1007, "LOG_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.ACCESS_MTP",
                shortLabel = "ACCESS_MTP",
                expectedGids = listOf(ExpectedGid(1024, "MTP_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.NET_ADMIN",
                shortLabel = "NET_ADMIN",
                expectedGids = listOf(ExpectedGid(3005, "NET_ADMIN_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.MAINLINE_NETWORK_STACK",
                shortLabel = "MAINLINE_NETWORK_STACK",
                expectedGids = listOf(
                    ExpectedGid(3005, "NET_ADMIN_GID"),
                    ExpectedGid(3004, "NET_RAW_GID"),
                ),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.ACCESS_CACHE_FILESYSTEM",
                shortLabel = "ACCESS_CACHE_FILESYSTEM",
                expectedGids = listOf(ExpectedGid(2001, "CACHE_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.DIAGNOSTIC",
                shortLabel = "DIAGNOSTIC",
                expectedGids = listOf(
                    ExpectedGid(1004, "INPUT_GID"),
                    ExpectedGid(2002, "DIAG_GID"),
                ),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.READ_NETWORK_USAGE_HISTORY",
                shortLabel = "READ_NETWORK_USAGE_HISTORY",
                expectedGids = listOf(ExpectedGid(3006, "NET_BW_STATS_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.UPDATE_DEVICE_STATS",
                shortLabel = "UPDATE_DEVICE_STATS",
                expectedGids = listOf(ExpectedGid(3007, "NET_BW_ACCT_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.LOOP_RADIO",
                shortLabel = "LOOP_RADIO",
                expectedGids = listOf(ExpectedGid(1030, "LOOP_RADIO_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.MANAGE_VOICE_KEYPHRASES",
                shortLabel = "MANAGE_VOICE_KEYPHRASES",
                expectedGids = listOf(ExpectedGid(1005, "AUDIO_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.ACCESS_BROADCAST_RADIO",
                shortLabel = "ACCESS_BROADCAST_RADIO",
                expectedGids = listOf(ExpectedGid(1013, "MEDIA_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.USE_RESERVED_DISK",
                shortLabel = "USE_RESERVED_DISK",
                expectedGids = listOf(ExpectedGid(1065, "RESERVED_DISK_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.WRITE_SECURITY_LOG",
                shortLabel = "WRITE_SECURITY_LOG",
                expectedGids = listOf(ExpectedGid(1091, "SECURITY_LOG_WRITER_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.VIRTUAL_INPUT_DEVICE",
                shortLabel = "VIRTUAL_INPUT_DEVICE",
                expectedGids = listOf(ExpectedGid(3011, "UHID_GID")),
            ),
            PermissionGidAuditRule(
                permission = "android.permission.MANAGE_VIRTUAL_MACHINE",
                shortLabel = "MANAGE_VIRTUAL_MACHINE",
                expectedGids = listOf(ExpectedGid(3013, "VIRTUAL_MACHINE_GID")),
            ),
        )
    }
}
