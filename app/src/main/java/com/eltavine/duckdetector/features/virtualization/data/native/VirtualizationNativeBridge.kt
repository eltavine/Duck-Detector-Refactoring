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

import com.eltavine.duckdetector.core.native.DuckDetectorNativeLibrary
import com.eltavine.duckdetector.core.native.NativeCollectionStatus
import com.eltavine.duckdetector.core.native.NativePayloadCodec
import com.eltavine.duckdetector.core.native.NativePayloadContract
import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

open class VirtualizationNativeBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {

    open fun isNativeAvailable(): Boolean = DuckDetectorNativeLibrary.isLoaded

    open fun collectSnapshot(): VirtualizationNativeSnapshot = collector.collect(
        readPayload = ::nativeCollectSnapshot,
        parse = ::parseSnapshot,
        unavailable = { status -> VirtualizationNativeSnapshot(collection = status) },
    )

    open fun runTimingTrap(): VirtualizationTrapResult = collectTrap(::nativeRunTimingTrap)

    open fun runSyscallParityTrap(): VirtualizationTrapResult =
        collectTrap(::nativeRunSyscallParityTrap)

    open fun runAsmCounterTrap(): VirtualizationTrapResult = collectTrap(::nativeRunAsmCounterTrap)

    open fun runAsmRawSyscallTrap(): VirtualizationTrapResult =
        collectTrap(::nativeRunAsmRawSyscallTrap)

    open fun runSacrificialSyscallPack(): SacrificialSyscallPackResult = collector.collect(
        readPayload = ::nativeRunSacrificialSyscallPack,
        parse = ::parseSacrificialSyscallPack,
        unavailable = { status ->
            SacrificialSyscallPackResult(detail = status.explain("Syscall pack did not run"))
        },
    )

    /**
     * All five traps read one payload and differ only in which entry point they call, so they share
     * the failure handling too. A trap that never ran reports why in [VirtualizationTrapResult.detail]
     * instead of returning zero suspicious attempts, which would read as a passing trap.
     */
    private fun collectTrap(readPayload: () -> String): VirtualizationTrapResult = collector.collect(
        readPayload = readPayload,
        parse = ::parseTrap,
        unavailable = { status ->
            VirtualizationTrapResult(detail = status.explain("Trap did not run"))
        },
    )

    internal fun parseSnapshot(raw: String): VirtualizationNativeSnapshot {
        if (raw.isBlank()) {
            return VirtualizationNativeSnapshot()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        var snapshot = VirtualizationNativeSnapshot()
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
                                group = parts[0].decodeValue(),
                                severity = parts[1].decodeValue(),
                                label = parts[2].decodeValue(),
                                value = parts[3].decodeValue(),
                                detail = parts[4].decodeValue(),
                            )
                        }
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        snapshot = when (key) {
                            "AVAILABLE" -> snapshot.copy(available = value.asBool())
                            "MAP_LINE_COUNT" -> snapshot.copy(
                                mapLineCount = value.toIntOrNull() ?: snapshot.mapLineCount,
                            )

                            "FD_COUNT" -> snapshot.copy(
                                fdCount = value.toIntOrNull() ?: snapshot.fdCount,
                            )

                            "MOUNTINFO_LINE_COUNT" -> snapshot.copy(
                                mountInfoCount = value.toIntOrNull() ?: snapshot.mountInfoCount,
                            )

                            "ENVIRONMENT_HITS" -> snapshot.copy(
                                environmentHitCount = value.toIntOrNull()
                                    ?: snapshot.environmentHitCount,
                            )

                            "TRANSLATION_HITS" -> snapshot.copy(
                                translationHitCount = value.toIntOrNull()
                                    ?: snapshot.translationHitCount,
                            )

                            "RUNTIME_HITS" -> snapshot.copy(
                                runtimeArtifactHitCount = value.toIntOrNull()
                                    ?: snapshot.runtimeArtifactHitCount,
                            )

                            "EGL_AVAILABLE" -> snapshot.copy(eglAvailable = value.asBool())
                            "EGL_VENDOR" -> snapshot.copy(eglVendor = value.decodeValue())
                            "EGL_RENDERER" -> snapshot.copy(eglRenderer = value.decodeValue())
                            "EGL_VERSION" -> snapshot.copy(eglVersion = value.decodeValue())
                            "MOUNT_NAMESPACE_INODE" -> snapshot.copy(
                                mountNamespaceInode = value.decodeValue(),
                            )

                            "APEX_MOUNT_KEY" -> snapshot.copy(apexMountKey = value.decodeValue())
                            "SYSTEM_MOUNT_KEY" -> snapshot.copy(systemMountKey = value.decodeValue())
                            "VENDOR_MOUNT_KEY" -> snapshot.copy(vendorMountKey = value.decodeValue())

                            else -> snapshot
                        }
                    }
                }
            }

        return snapshot.copy(findings = findings)
    }

    fun parseSacrificialSyscallPack(raw: String): SacrificialSyscallPackResult {
        if (raw.isBlank()) {
            return SacrificialSyscallPackResult()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        var available = false
        var supported = false
        var disabled = false
        var detail = ""
        val itemOrder = mutableListOf<String>()
        val supportedByLabel = linkedMapOf<String, Boolean>()
        val completedByLabel = linkedMapOf<String, Int>()
        val suspiciousByLabel = linkedMapOf<String, Int>()
        val detailByLabel = linkedMapOf<String, String>()
        val attemptsByLabel = linkedMapOf<String, MutableList<VirtualizationTrapAttempt>>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("ITEM=") -> {
                        val parts = line.removePrefix("ITEM=").split('\t', limit = 5)
                        val label = parts.getOrNull(0).orEmpty()
                        if (label.isBlank()) {
                            return@forEach
                        }
                        if (label !in itemOrder) {
                            itemOrder += label
                        }
                        supportedByLabel[label] = parts.getOrNull(1).asBool()
                        completedByLabel[label] = parts.getOrNull(2)?.toIntOrNull() ?: 0
                        suspiciousByLabel[label] = parts.getOrNull(3)?.toIntOrNull() ?: 0
                        detailByLabel[label] = parts.getOrNull(4).orEmpty().decodeValue()
                    }

                    line.startsWith("ATTEMPT=") -> {
                        val parts = line.removePrefix("ATTEMPT=").split('\t', limit = 3)
                        val label = parts.getOrNull(0).orEmpty()
                        if (label.isBlank()) {
                            return@forEach
                        }
                        attemptsByLabel.getOrPut(label) { mutableListOf() } +=
                            VirtualizationTrapAttempt(
                                suspicious = parts.getOrNull(1).asBool(),
                                detail = parts.getOrNull(2).orEmpty().decodeValue(),
                            )
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        when (key) {
                            "AVAILABLE" -> available = value.asBool()
                            "SUPPORTED" -> supported = value.asBool()
                            "DISABLED" -> disabled = value.asBool()
                            "DETAIL" -> detail = value.decodeValue()
                        }
                    }
                }
            }

        val items = itemOrder.map { label ->
            VirtualizationSyscallPackItem(
                label = label,
                supported = supportedByLabel[label] == true,
                completedAttempts = completedByLabel[label] ?: 0,
                suspiciousAttempts = suspiciousByLabel[label] ?: 0,
                attempts = attemptsByLabel[label].orEmpty(),
                detail = detailByLabel[label].orEmpty(),
            )
        }

        return SacrificialSyscallPackResult(
            available = available,
            supported = supported,
            disabled = disabled,
            detail = detail,
            items = items,
        )
    }

    internal fun parseTrap(raw: String): VirtualizationTrapResult {
        if (raw.isBlank()) {
            return VirtualizationTrapResult()
        }

        NativePayloadContract.requireKeys(raw, "AVAILABLE")

        var available = false
        var supported = false
        var completedAttempts = 0
        var suspiciousAttempts = 0
        var detail = ""
        val attempts = mutableListOf<VirtualizationTrapAttempt>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("ATTEMPT=") -> {
                        val parts = line.removePrefix("ATTEMPT=").split('\t', limit = 2)
                        attempts += VirtualizationTrapAttempt(
                            suspicious = parts.firstOrNull().asBool(),
                            detail = parts.getOrNull(1).orEmpty().decodeValue(),
                        )
                    }

                    line.contains('=') -> {
                        val key = line.substringBefore('=')
                        val value = line.substringAfter('=')
                        when (key) {
                            "AVAILABLE" -> available = value.asBool()
                            "SUPPORTED" -> supported = value.asBool()
                            "COMPLETED_ATTEMPTS" -> completedAttempts = value.toIntOrNull() ?: 0
                            "SUSPICIOUS_ATTEMPTS" -> suspiciousAttempts = value.toIntOrNull() ?: 0
                            "DETAIL" -> detail = value.decodeValue()
                        }
                    }
                }
            }

        return VirtualizationTrapResult(
            available = available,
            supported = supported,
            completedAttempts = completedAttempts,
            suspiciousAttempts = suspiciousAttempts,
            attempts = attempts,
            detail = detail,
        )
    }

    private fun String.decodeValue(): String = NativePayloadCodec.decodeValue(this)

    private fun String?.asBool(): Boolean = NativePayloadCodec.decodeFlag(this)

    private external fun nativeCollectSnapshot(): String
    private external fun nativeRunTimingTrap(): String
    private external fun nativeRunSyscallParityTrap(): String
    private external fun nativeRunAsmCounterTrap(): String
    private external fun nativeRunAsmRawSyscallTrap(): String
    private external fun nativeRunSacrificialSyscallPack(): String
}

data class VirtualizationNativeSnapshot(
    val available: Boolean = false,
    val eglAvailable: Boolean = false,
    val eglVendor: String = "",
    val eglRenderer: String = "",
    val eglVersion: String = "",
    val mountNamespaceInode: String = "",
    val apexMountKey: String = "",
    val systemMountKey: String = "",
    val vendorMountKey: String = "",
    val mapLineCount: Int = 0,
    val fdCount: Int = 0,
    val mountInfoCount: Int = 0,
    val environmentHitCount: Int = 0,
    val translationHitCount: Int = 0,
    val runtimeArtifactHitCount: Int = 0,
    val findings: List<VirtualizationNativeFinding> = emptyList(),
    /**
     * Why this snapshot is or is not usable. [available] alone cannot distinguish "the probe ran and
     * found nothing" from "the probe never ran", so the reason is carried here.
     */
    val collection: NativeCollectionStatus = NativeCollectionStatus.Collected,
) {
    val artifactKeys: Set<String>
        get() = findings.mapTo(linkedSetOf()) { "${it.group}:${it.label}:${it.value}" }
}

data class VirtualizationNativeFinding(
    val group: String,
    val severity: String,
    val label: String,
    val value: String,
    val detail: String,
)

data class VirtualizationTrapResult(
    val available: Boolean = false,
    val supported: Boolean = false,
    val completedAttempts: Int = 0,
    val suspiciousAttempts: Int = 0,
    val attempts: List<VirtualizationTrapAttempt> = emptyList(),
    val detail: String = "",
) {
    val suspicious: Boolean
        get() = supported && completedAttempts >= 2 && suspiciousAttempts >= 2

    val clean: Boolean
        get() = supported && completedAttempts >= 2 && suspiciousAttempts == 0
}

data class VirtualizationTrapAttempt(
    val suspicious: Boolean,
    val detail: String,
)

data class SacrificialSyscallPackResult(
    val available: Boolean = false,
    val supported: Boolean = false,
    val disabled: Boolean = false,
    val detail: String = "",
    val items: List<VirtualizationSyscallPackItem> = emptyList(),
) {
    val suspiciousItems: List<VirtualizationSyscallPackItem>
        get() = items.filter { it.suspicious }

    val hitCount: Int
        get() = suspiciousItems.size
}

data class VirtualizationSyscallPackItem(
    val label: String,
    val supported: Boolean = false,
    val completedAttempts: Int = 0,
    val suspiciousAttempts: Int = 0,
    val attempts: List<VirtualizationTrapAttempt> = emptyList(),
    val detail: String = "",
) {
    val suspicious: Boolean
        get() = supported && completedAttempts >= 2 && suspiciousAttempts >= 2

    val clean: Boolean
        get() = supported && completedAttempts >= 2 && suspiciousAttempts == 0
}
