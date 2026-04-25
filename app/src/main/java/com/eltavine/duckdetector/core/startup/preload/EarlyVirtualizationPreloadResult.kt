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

package com.eltavine.duckdetector.core.startup.preload

import android.content.Intent
import android.os.Bundle

enum class EarlyVirtualizationPreloadSource {
    NONE,
    INTENT,
    NATIVE,
}

enum class EarlyVirtualizationPreloadSignal(
    val key: String,
    val label: String,
    val isDanger: Boolean,
) {
    QEMU_PROPERTY("QEMU_PROPERTY", "QEMU property", true),
    EMULATOR_HARDWARE("EMULATOR_HARDWARE", "Emulator hardware", true),
    DEVICE_NODE("DEVICE_NODE", "Emulator device node", true),
    AVF_RUNTIME("AVF_RUNTIME", "AVF runtime", true),
    AUTHFS_RUNTIME("AUTHFS_RUNTIME", "authfs runtime", true),
    NATIVE_BRIDGE("NATIVE_BRIDGE", "Native bridge", false),
}

data class EarlyVirtualizationPreloadCapturedExtras(
    val hasRun: Boolean = false,
    val detected: Boolean = false,
    val detectionMethod: String = "",
    val details: String = "",
    val contextValid: Boolean = true,
    val mountNamespaceInode: String = "",
    val apexMountKey: String = "",
    val systemMountKey: String = "",
    val vendorMountKey: String = "",
    val qemuPropertyDetected: Boolean = false,
    val emulatorHardwareDetected: Boolean = false,
    val deviceNodeDetected: Boolean = false,
    val avfRuntimeDetected: Boolean = false,
    val authfsRuntimeDetected: Boolean = false,
    val nativeBridgeDetected: Boolean = false,
)

data class EarlyVirtualizationPreloadResult(
    val hasRun: Boolean = false,
    val detected: Boolean = false,
    val detectionMethod: String = "",
    val details: String = "",
    val mountNamespaceInode: String = "",
    val apexMountKey: String = "",
    val systemMountKey: String = "",
    val vendorMountKey: String = "",
    val qemuPropertyDetected: Boolean = false,
    val emulatorHardwareDetected: Boolean = false,
    val deviceNodeDetected: Boolean = false,
    val avfRuntimeDetected: Boolean = false,
    val authfsRuntimeDetected: Boolean = false,
    val nativeBridgeDetected: Boolean = false,
    val findings: List<String> = emptyList(),
    val isContextValid: Boolean = false,
    val source: EarlyVirtualizationPreloadSource = EarlyVirtualizationPreloadSource.NONE,
) {
    val available: Boolean
        get() = hasRun

    val activeSignals: List<EarlyVirtualizationPreloadSignal>
        get() = buildList {
            if (qemuPropertyDetected) add(EarlyVirtualizationPreloadSignal.QEMU_PROPERTY)
            if (emulatorHardwareDetected) add(EarlyVirtualizationPreloadSignal.EMULATOR_HARDWARE)
            if (deviceNodeDetected) add(EarlyVirtualizationPreloadSignal.DEVICE_NODE)
            if (avfRuntimeDetected) add(EarlyVirtualizationPreloadSignal.AVF_RUNTIME)
            if (authfsRuntimeDetected) add(EarlyVirtualizationPreloadSignal.AUTHFS_RUNTIME)
            if (nativeBridgeDetected) add(EarlyVirtualizationPreloadSignal.NATIVE_BRIDGE)
        }

    val findingCount: Int
        get() = activeSignals.size

    val hasDangerSignal: Boolean
        get() = activeSignals.any { it.isDanger }

    val hasWarningSignal: Boolean
        get() = activeSignals.any { !it.isDanger }

    fun normalize(): EarlyVirtualizationPreloadResult {
        val resolvedSignals = activeSignals
        val resolvedDetected = detected || resolvedSignals.isNotEmpty()
        val resolvedMethod = detectionMethod.ifBlank {
            resolvedSignals.joinToString(separator = ", ") { it.label }.ifBlank { "None" }
        }
        val resolvedDetails = details.ifBlank {
            when {
                !hasRun -> "Startup virtualization preload did not run."
                resolvedDetected -> "Startup preload detected: $resolvedMethod"
                else -> "Startup virtualization preload completed without anomalies."
            }
        }
        val resolvedFindings = if (findings.isNotEmpty()) {
            findings.distinct()
        } else {
            resolvedSignals.map { signal ->
                "${signal.key}|${signal.label}|${if (signal.isDanger) "DANGER" else "WARNING"}"
            }
        }
        return copy(
            detected = resolvedDetected,
            detectionMethod = resolvedMethod,
            details = resolvedDetails,
            findings = resolvedFindings,
        )
    }

    companion object {
        const val KEY_HAS_RUN = "early_virtualization_has_run"
        const val KEY_DETECTED = "early_virtualization_detected"
        const val KEY_DETECTION_METHOD = "early_virtualization_method"
        const val KEY_DETAILS = "early_virtualization_details"
        const val KEY_CONTEXT_VALID = "early_virtualization_context_valid"
        const val KEY_MOUNT_NAMESPACE_INODE = "early_virtualization_mount_namespace_inode"
        const val KEY_APEX_MOUNT_KEY = "early_virtualization_apex_mount_key"
        const val KEY_SYSTEM_MOUNT_KEY = "early_virtualization_system_mount_key"
        const val KEY_VENDOR_MOUNT_KEY = "early_virtualization_vendor_mount_key"
        const val KEY_QEMU_PROPERTY = "early_virtualization_qemu_property"
        const val KEY_EMULATOR_HARDWARE = "early_virtualization_emulator_hardware"
        const val KEY_DEVICE_NODE = "early_virtualization_device_node"
        const val KEY_AVF_RUNTIME = "early_virtualization_avf_runtime"
        const val KEY_AUTHFS_RUNTIME = "early_virtualization_authfs_runtime"
        const val KEY_NATIVE_BRIDGE = "early_virtualization_native_bridge"

        fun empty(
            source: EarlyVirtualizationPreloadSource = EarlyVirtualizationPreloadSource.NONE,
        ): EarlyVirtualizationPreloadResult {
            return EarlyVirtualizationPreloadResult(source = source)
        }

        fun fromIntent(intent: Intent?): EarlyVirtualizationPreloadResult =
            fromBundle(intent?.extras)

        fun fromBundle(bundle: Bundle?): EarlyVirtualizationPreloadResult {
            if (bundle == null) {
                return empty()
            }
            val inferredHasRun = bundle.getBoolean(KEY_HAS_RUN, false) ||
                    bundle.containsKey(KEY_DETECTED) ||
                    bundle.containsKey(KEY_DETECTION_METHOD) ||
                    bundle.containsKey(KEY_DETAILS) ||
                    bundle.containsKey(KEY_MOUNT_NAMESPACE_INODE) ||
                    bundle.containsKey(KEY_APEX_MOUNT_KEY) ||
                    bundle.containsKey(KEY_SYSTEM_MOUNT_KEY) ||
                    bundle.containsKey(KEY_VENDOR_MOUNT_KEY) ||
                    bundle.containsKey(KEY_QEMU_PROPERTY) ||
                    bundle.containsKey(KEY_EMULATOR_HARDWARE) ||
                    bundle.containsKey(KEY_DEVICE_NODE) ||
                    bundle.containsKey(KEY_AVF_RUNTIME) ||
                    bundle.containsKey(KEY_AUTHFS_RUNTIME) ||
                    bundle.containsKey(KEY_NATIVE_BRIDGE)
            return fromCapturedExtras(
                EarlyVirtualizationPreloadCapturedExtras(
                    hasRun = inferredHasRun,
                    detected = bundle.getBoolean(KEY_DETECTED, false),
                    detectionMethod = bundle.getString(KEY_DETECTION_METHOD).orEmpty(),
                    details = bundle.getString(KEY_DETAILS).orEmpty(),
                    mountNamespaceInode = bundle.getString(KEY_MOUNT_NAMESPACE_INODE).orEmpty(),
                    apexMountKey = bundle.getString(KEY_APEX_MOUNT_KEY).orEmpty(),
                    systemMountKey = bundle.getString(KEY_SYSTEM_MOUNT_KEY).orEmpty(),
                    vendorMountKey = bundle.getString(KEY_VENDOR_MOUNT_KEY).orEmpty(),
                    contextValid = if (bundle.containsKey(KEY_CONTEXT_VALID)) {
                        bundle.getBoolean(KEY_CONTEXT_VALID, false)
                    } else {
                        inferredHasRun
                    },
                    qemuPropertyDetected = bundle.getBoolean(KEY_QEMU_PROPERTY, false),
                    emulatorHardwareDetected = bundle.getBoolean(KEY_EMULATOR_HARDWARE, false),
                    deviceNodeDetected = bundle.getBoolean(KEY_DEVICE_NODE, false),
                    avfRuntimeDetected = bundle.getBoolean(KEY_AVF_RUNTIME, false),
                    authfsRuntimeDetected = bundle.getBoolean(KEY_AUTHFS_RUNTIME, false),
                    nativeBridgeDetected = bundle.getBoolean(KEY_NATIVE_BRIDGE, false),
                ),
            )
        }

        internal fun fromCapturedExtras(
            extras: EarlyVirtualizationPreloadCapturedExtras,
        ): EarlyVirtualizationPreloadResult {
            return EarlyVirtualizationPreloadResult(
                hasRun = extras.hasRun,
                detected = extras.detected,
                detectionMethod = extras.detectionMethod,
                details = extras.details,
                mountNamespaceInode = extras.mountNamespaceInode,
                apexMountKey = extras.apexMountKey,
                systemMountKey = extras.systemMountKey,
                vendorMountKey = extras.vendorMountKey,
                qemuPropertyDetected = extras.qemuPropertyDetected,
                emulatorHardwareDetected = extras.emulatorHardwareDetected,
                deviceNodeDetected = extras.deviceNodeDetected,
                avfRuntimeDetected = extras.avfRuntimeDetected,
                authfsRuntimeDetected = extras.authfsRuntimeDetected,
                nativeBridgeDetected = extras.nativeBridgeDetected,
                isContextValid = extras.contextValid,
                source = EarlyVirtualizationPreloadSource.INTENT,
            ).normalize()
        }

        internal fun fromCapturedValues(
            values: Map<String, Any?>,
        ): EarlyVirtualizationPreloadResult {
            val inferredHasRun = values.boolean(KEY_HAS_RUN) ||
                    values.containsKey(KEY_DETECTED) ||
                    values.containsKey(KEY_DETECTION_METHOD) ||
                    values.containsKey(KEY_DETAILS) ||
                    values.containsKey(KEY_MOUNT_NAMESPACE_INODE) ||
                    values.containsKey(KEY_APEX_MOUNT_KEY) ||
                    values.containsKey(KEY_SYSTEM_MOUNT_KEY) ||
                    values.containsKey(KEY_VENDOR_MOUNT_KEY) ||
                    values.containsKey(KEY_QEMU_PROPERTY) ||
                    values.containsKey(KEY_EMULATOR_HARDWARE) ||
                    values.containsKey(KEY_DEVICE_NODE) ||
                    values.containsKey(KEY_AVF_RUNTIME) ||
                    values.containsKey(KEY_AUTHFS_RUNTIME) ||
                    values.containsKey(KEY_NATIVE_BRIDGE)
            return fromCapturedExtras(
                EarlyVirtualizationPreloadCapturedExtras(
                    hasRun = inferredHasRun,
                    detected = values.boolean(KEY_DETECTED),
                    detectionMethod = values.string(KEY_DETECTION_METHOD),
                    details = values.string(KEY_DETAILS),
                    mountNamespaceInode = values.string(KEY_MOUNT_NAMESPACE_INODE),
                    apexMountKey = values.string(KEY_APEX_MOUNT_KEY),
                    systemMountKey = values.string(KEY_SYSTEM_MOUNT_KEY),
                    vendorMountKey = values.string(KEY_VENDOR_MOUNT_KEY),
                    contextValid = if (values.containsKey(KEY_CONTEXT_VALID)) {
                        values.boolean(KEY_CONTEXT_VALID)
                    } else {
                        inferredHasRun
                    },
                    qemuPropertyDetected = values.boolean(KEY_QEMU_PROPERTY),
                    emulatorHardwareDetected = values.boolean(KEY_EMULATOR_HARDWARE),
                    deviceNodeDetected = values.boolean(KEY_DEVICE_NODE),
                    avfRuntimeDetected = values.boolean(KEY_AVF_RUNTIME),
                    authfsRuntimeDetected = values.boolean(KEY_AUTHFS_RUNTIME),
                    nativeBridgeDetected = values.boolean(KEY_NATIVE_BRIDGE),
                ),
            )
        }

        private fun Map<String, Any?>.boolean(key: String): Boolean {
            val value = this[key] ?: return false
            return when (value) {
                is Boolean -> value
                is Number -> value.toInt() != 0
                is String -> value.equals("true", ignoreCase = true) || value == "1"
                else -> false
            }
        }

        private fun Map<String, Any?>.string(key: String): String {
            return (this[key] as? String).orEmpty()
        }
    }
}
