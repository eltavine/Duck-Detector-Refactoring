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

package com.eltavine.duckdetector.features.nativeroot.data.native

import android.os.Build

class NativeRootNativeBridge {

    fun collectSnapshot(): NativeRootNativeSnapshot {
        val skipKsuSupercall = shouldSkipKsuSupercall(
            manufacturer = Build.MANUFACTURER,
            brand = Build.BRAND,
        )
        return runCatching {
            parse(nativeCollectSnapshot(skipKsuSupercall))
        }.getOrDefault(NativeRootNativeSnapshot())
    }

    internal fun shouldSkipKsuSupercall(
        manufacturer: String?,
        brand: String?,
    ): Boolean {
        val normalizedManufacturer = manufacturer.orEmpty().trim().lowercase()
        val normalizedBrand = brand.orEmpty().trim().lowercase()
        return normalizedManufacturer in KSU_SUPERCALL_BLOCKLIST ||
            normalizedBrand in KSU_SUPERCALL_BLOCKLIST
    }

    internal fun parse(raw: String): NativeRootNativeSnapshot {
        if (raw.isBlank()) {
            return NativeRootNativeSnapshot()
        }

        var snapshot = NativeRootNativeSnapshot()
        val findings = mutableListOf<NativeRootNativeFinding>()

        raw.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when {
                    line.startsWith("FINDING=") -> {
                        val parts = line.removePrefix("FINDING=").split('\t', limit = 5)
                        if (parts.size == 5) {
                            findings += NativeRootNativeFinding(
                                group = parts[0],
                                severity = parts[1],
                                label = parts[2].decodeValue(),
                                value = parts[3].decodeValue(),
                                detail = parts[4].decodeValue(),
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

    private fun NativeRootNativeSnapshot.applyEntry(
        key: String,
        value: String,
    ): NativeRootNativeSnapshot {
        return when (key) {
            "AVAILABLE" -> copy(available = value.asBool())
            "KERNELSU" -> copy(kernelSuDetected = value.asBool())
            "APATCH" -> copy(aPatchDetected = value.asBool())
            "MAGISK" -> copy(magiskDetected = value.asBool())
            "SUSFS" -> copy(susfsDetected = value.asBool())
            "KSU_VERSION" -> copy(kernelSuVersion = value.toLongOrNull() ?: kernelSuVersion)
            "PRCTL_HIT" -> copy(prctlProbeHit = value.asBool())
            "KSU_SUPERCALL_ATTEMPTED" -> copy(ksuSupercallAttempted = value.asBool())
            "KSU_SUPERCALL_HIT" -> copy(ksuSupercallProbeHit = value.asBool())
            "KSU_SUPERCALL_BLOCKED" -> copy(ksuSupercallBlocked = value.asBool())
            "KSU_SUPERCALL_SAFE_MODE" -> copy(ksuSupercallSafeMode = value.asBool())
            "KSU_SUPERCALL_LKM" -> copy(ksuSupercallLkm = value.asBool())
            "KSU_SUPERCALL_LATE_LOAD" -> copy(ksuSupercallLateLoad = value.asBool())
            "KSU_SUPERCALL_PR_BUILD" -> copy(ksuSupercallPrBuild = value.asBool())
            "KSU_SUPERCALL_MANAGER" -> copy(ksuSupercallManager = value.asBool())
            "SUSFS_HIT" -> copy(susfsProbeHit = value.asBool())
            "SELF_SU_DOMAIN" -> copy(selfSuDomain = value.asBool())
            "SELF_CONTEXT" -> copy(selfContext = value.decodeValue())
            "SELF_KSU_DRIVER_FDS" -> copy(
                selfKsuDriverFdCount = value.toIntOrNull() ?: selfKsuDriverFdCount
            )

            "SELF_KSU_FDWRAPPER_FDS" -> copy(
                selfKsuFdwrapperFdCount = value.toIntOrNull() ?: selfKsuFdwrapperFdCount
            )

            "PATH_HITS" -> copy(pathHitCount = value.toIntOrNull() ?: pathHitCount)
            "PATH_CHECKS" -> copy(pathCheckCount = value.toIntOrNull() ?: pathCheckCount)
            "PROCESS_HITS" -> copy(processHitCount = value.toIntOrNull() ?: processHitCount)
            "PROCESS_CHECKED" -> copy(
                processCheckedCount = value.toIntOrNull() ?: processCheckedCount
            )

            "PROCESS_DENIED" -> copy(processDeniedCount = value.toIntOrNull() ?: processDeniedCount)
            "KERNEL_HITS" -> copy(kernelHitCount = value.toIntOrNull() ?: kernelHitCount)
            "KERNEL_SOURCES" -> copy(kernelSourceCount = value.toIntOrNull() ?: kernelSourceCount)
            "PROPERTY_HITS" -> copy(propertyHitCount = value.toIntOrNull() ?: propertyHitCount)
            "PROPERTY_CHECKS" -> copy(
                propertyCheckCount = value.toIntOrNull() ?: propertyCheckCount
            )

            else -> this
        }
    }

    private fun String.asBool(): Boolean {
        return this == "1" || equals("true", ignoreCase = true)
    }

    private fun String.decodeValue(): String {
        return buildString(length) {
            var index = 0
            while (index < this@decodeValue.length) {
                val current = this@decodeValue[index]
                if (current == '\\' && index + 1 < this@decodeValue.length) {
                    when (this@decodeValue[index + 1]) {
                        'n' -> {
                            append('\n')
                            index += 2
                            continue
                        }

                        'r' -> {
                            append('\r')
                            index += 2
                            continue
                        }

                        't' -> {
                            append('\t')
                            index += 2
                            continue
                        }

                        '\\' -> {
                            append('\\')
                            index += 2
                            continue
                        }
                    }
                }
                append(current)
                index += 1
            }
        }
    }

    private external fun nativeCollectSnapshot(skipKsuSupercall: Boolean): String

    companion object {
        private val KSU_SUPERCALL_BLOCKLIST = setOf("xiaomi", "redmi", "poco")

        init {
            runCatching { System.loadLibrary("duckdetector") }
        }
    }
}
