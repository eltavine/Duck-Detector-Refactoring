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

package com.eltavine.duckdetector.features.systemproperties.data.repository

import android.os.Build
import com.eltavine.duckdetector.features.systemproperties.data.native.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.systemproperties.data.rules.SystemPropertiesCatalog
import com.eltavine.duckdetector.features.systemproperties.data.rules.SystemPropertyRule
import com.eltavine.duckdetector.features.systemproperties.data.utils.MultiSourcePropertyRead
import com.eltavine.duckdetector.features.systemproperties.data.utils.SystemPropertyConsistencyUtils
import com.eltavine.duckdetector.features.systemproperties.data.utils.SystemPropertyReadUtils
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodOutcome
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesMethodResult
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesReport
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertiesStage
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SystemPropertiesRepository(
    private val readUtils: SystemPropertyReadUtils = SystemPropertyReadUtils(),
    private val consistencyUtils: SystemPropertyConsistencyUtils = SystemPropertyConsistencyUtils(),
) {

    suspend fun scan(): SystemPropertiesReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                SystemPropertiesReport.failed(throwable.message ?: "System Properties scan failed.")
            }
    }

    private fun scanInternal(): SystemPropertiesReport {
        val trackedProperties =
            (SystemPropertiesCatalog.rules.map { it.property } + SystemPropertiesCatalog.infoProperties)
                .distinct()
        val nativeSnapshot = readUtils.collectNativeSnapshot(trackedProperties)
        val propertyCache = linkedMapOf<String, MultiSourcePropertyRead>()
        val ruleSignals = mutableListOf<SystemPropertySignal>()
        val infoSignals = mutableListOf<SystemPropertySignal>()

        SystemPropertiesCatalog.rules.forEach { rule ->
            if (rule.property == SERVICE_ADB_ROOT) {
                return@forEach
            }
            val read = readUtils.readProperty(
                property = rule.property,
                category = rule.category,
                cache = propertyCache,
                nativeSnapshot = nativeSnapshot,
            )
            if (read.preferredValue.isBlank()) {
                return@forEach
            }
            ruleSignals += buildRuleSignal(rule, read)
        }

        buildAdbRootSignal(propertyCache, nativeSnapshot)?.let(ruleSignals::add)

        SystemPropertiesCatalog.infoProperties.forEach { property ->
            val read = readUtils.readProperty(
                property = property,
                category = infoCategory(property),
                cache = propertyCache,
                nativeSnapshot = nativeSnapshot,
            )
            if (read.preferredValue.isBlank()) {
                return@forEach
            }
            if (ruleSignals.none { it.property == property }) {
                infoSignals += buildInfoSignal(property, read)
            }
        }

        val buildSignals = buildBuildConstantSignals()
        val sourceSignals = consistencyUtils.buildSourceMismatchSignals(propertyCache.values)
        val consistencySignals = consistencyUtils.buildConsistencySignals(
            readsByProperty = propertyCache,
            nativeSnapshot = nativeSnapshot,
        )
        val readOnlySerialSignals = buildReadOnlySerialSignals(nativeSnapshot)
        val propAreaSignals = buildPropAreaSignals(nativeSnapshot)

        val allSignals =
            ruleSignals +
                    buildSignals +
                    sourceSignals +
                    consistencySignals +
                    readOnlySerialSignals +
                    propAreaSignals
        if (
            allSignals.isEmpty() &&
            infoSignals.isEmpty() &&
            !nativeSnapshot.propAreaAvailable &&
            !nativeSnapshot.readOnlySerialAvailable
        ) {
            return SystemPropertiesReport.failed(
                "No readable system properties, raw boot parameters, or build constants were collected.",
            )
        }

        val observedRuleCount =
            ruleSignals.count { it.category != SystemPropertyCategory.SOURCE_CONSISTENCY }
        val reflectionHitCount = propertyCache.values.count {
            it.sourceValues[SystemPropertySource.REFLECTION].isNullOrBlank().not()
        }
        val getpropHitCount = propertyCache.values.count {
            it.sourceValues[SystemPropertySource.GETPROP].isNullOrBlank().not()
        }
        val jvmHitCount = propertyCache.values.count {
            it.sourceValues[SystemPropertySource.JVM].isNullOrBlank().not()
        }

        return SystemPropertiesReport(
            stage = SystemPropertiesStage.READY,
            signals = allSignals,
            infoSignals = infoSignals,
            checkedRuleCount = SystemPropertiesCatalog.rules.size,
            observedRuleCount = observedRuleCount,
            infoPropertyCount = infoSignals.size,
            reflectionHitCount = reflectionHitCount,
            getpropHitCount = getpropHitCount,
            jvmHitCount = jvmHitCount,
            nativeHitCount = nativeSnapshot.nativePropertyHitCount,
            bootParamHitCount = nativeSnapshot.bootParamHitCount,
            buildSignalCount = buildSignals.size,
            propAreaAvailable = nativeSnapshot.propAreaAvailable,
            propAreaContextCount = nativeSnapshot.propAreaContextCount,
            propAreaHoleCount = nativeSnapshot.propAreaHoleCount,
            readOnlySerialAvailable = nativeSnapshot.readOnlySerialAvailable,
            readOnlySerialCheckedCount = nativeSnapshot.readOnlySerialCheckedCount,
            readOnlySerialFindingCount = nativeSnapshot.readOnlySerialFindingCount,
            methods = buildMethods(
                ruleSignals = ruleSignals,
                infoSignals = infoSignals,
                reflectionHitCount = reflectionHitCount,
                getpropHitCount = getpropHitCount,
                jvmHitCount = jvmHitCount,
                nativeHitCount = nativeSnapshot.nativePropertyHitCount,
                bootParamHitCount = nativeSnapshot.bootParamHitCount,
                observedRuleCount = observedRuleCount,
                buildSignals = buildSignals,
                sourceSignals = sourceSignals,
                consistencySignals = consistencySignals,
                readOnlySerialSignals = readOnlySerialSignals,
                readOnlySerialAvailable = nativeSnapshot.readOnlySerialAvailable,
                readOnlySerialCheckedCount = nativeSnapshot.readOnlySerialCheckedCount,
                readOnlySerialFindingCount = nativeSnapshot.readOnlySerialFindingCount,
                propAreaSignals = propAreaSignals,
                propAreaAvailable = nativeSnapshot.propAreaAvailable,
                propAreaContextCount = nativeSnapshot.propAreaContextCount,
                propAreaHoleCount = nativeSnapshot.propAreaHoleCount,
            ),
        )
    }

    private fun buildRuleSignal(
        rule: SystemPropertyRule,
        read: MultiSourcePropertyRead,
    ): SystemPropertySignal {
        val severity = when {
            matchesDanger(rule, read.preferredValue) -> SystemPropertySeverity.DANGER
            matchesWarning(rule, read.preferredValue) -> SystemPropertySeverity.WARNING
            rule.expectedSafeValue?.equals(
                read.preferredValue,
                ignoreCase = true
            ) == true -> SystemPropertySeverity.SAFE

            else -> SystemPropertySeverity.NEUTRAL
        }

        return SystemPropertySignal(
            property = rule.property,
            description = rule.description,
            value = read.preferredValue,
            category = rule.category,
            severity = severity,
            source = read.preferredSource,
            detail = buildString {
                append(rule.description)
                append(" via ")
                append(sourceLabel(read.preferredSource))
                rule.expectedSafeValue?.let { safe ->
                    append(". Expected safe value: ")
                    append(safe)
                }
                if (read.sourceValues.count { it.value.isNotBlank() } > 1) {
                    append(". Cross-checked across ")
                    append(read.sourceValues.count { it.value.isNotBlank() })
                    append(" sources.")
                }
            },
        )
    }

    private fun buildAdbRootSignal(
        cache: MutableMap<String, MultiSourcePropertyRead>,
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): SystemPropertySignal? {
        val adbRoot = readUtils.readProperty(
            property = SERVICE_ADB_ROOT,
            category = SystemPropertyCategory.SECURITY_CORE,
            cache = cache,
            nativeSnapshot = nativeSnapshot,
        )
        if (adbRoot.preferredValue.isBlank()) {
            return null
        }
        val debuggable = readUtils.readProperty(
            property = "ro.debuggable",
            category = SystemPropertyCategory.SECURITY_CORE,
            cache = cache,
            nativeSnapshot = nativeSnapshot,
        ).preferredValue
        val severity = when {
            adbRoot.preferredValue == "1" && debuggable == "1" -> SystemPropertySeverity.DANGER
            adbRoot.preferredValue == "1" -> SystemPropertySeverity.WARNING
            adbRoot.preferredValue == "0" -> SystemPropertySeverity.SAFE
            else -> SystemPropertySeverity.NEUTRAL
        }
        val detail = when {
            adbRoot.preferredValue == "1" && debuggable == "1" ->
                "adbd can remain root because service.adb.root=1 and ro.debuggable=1."

            adbRoot.preferredValue == "1" ->
                "service.adb.root is set, but ro.debuggable=$debuggable means adbd may not actually stay root."

            adbRoot.preferredValue == "0" ->
                "ADB root property is disabled."

            else ->
                "ADB root property is present but does not match the usual production values."
        }
        return SystemPropertySignal(
            property = SERVICE_ADB_ROOT,
            description = "ADB running as root",
            value = adbRoot.preferredValue,
            category = SystemPropertyCategory.SECURITY_CORE,
            severity = severity,
            source = adbRoot.preferredSource,
            detail = detail,
        )
    }

    private fun buildInfoSignal(
        property: String,
        read: MultiSourcePropertyRead,
    ): SystemPropertySignal {
        return SystemPropertySignal(
            property = property,
            description = friendlyInfoLabel(property),
            value = read.preferredValue,
            category = read.category,
            severity = SystemPropertySeverity.NEUTRAL,
            source = read.preferredSource,
            detail = "Collected via ${sourceLabel(read.preferredSource)}.",
        )
    }

    private fun buildBuildConstantSignals(): List<SystemPropertySignal> {
        val signals = mutableListOf<SystemPropertySignal>()

        Build.TYPE.takeIf { it.isNotBlank() }?.let { type ->
            val severity = when (type.lowercase()) {
                "eng", "userdebug" -> SystemPropertySeverity.DANGER
                "user" -> SystemPropertySeverity.SAFE
                else -> SystemPropertySeverity.NEUTRAL
            }
            signals += SystemPropertySignal(
                property = "Build.TYPE",
                description = "Build type constant",
                value = type,
                category = SystemPropertyCategory.BUILD_PROFILE,
                severity = severity,
                source = SystemPropertySource.BUILD,
                detail = "Collected from android.os.Build.TYPE.",
            )
        }

        Build.TAGS?.takeIf { it.isNotBlank() }?.let { tags ->
            val severity = when {
                tags.contains("test-keys", ignoreCase = true) ||
                        tags.contains(
                            "dev-keys",
                            ignoreCase = true
                        ) -> SystemPropertySeverity.DANGER

                tags.contains("release-keys", ignoreCase = true) -> SystemPropertySeverity.SAFE
                else -> SystemPropertySeverity.NEUTRAL
            }
            signals += SystemPropertySignal(
                property = "Build.TAGS",
                description = "Build signature tags",
                value = tags,
                category = SystemPropertyCategory.BUILD_PROFILE,
                severity = severity,
                source = SystemPropertySource.BUILD,
                detail = "Collected from android.os.Build.TAGS.",
            )
        }

        Build.FINGERPRINT.takeIf { it.isNotBlank() }?.let { fingerprint ->
            val matchedPattern =
                SystemPropertiesCatalog.suspiciousFingerprintPatterns.firstOrNull { pattern ->
                    fingerprint.contains(pattern, ignoreCase = true)
                }
            signals += SystemPropertySignal(
                property = "Build.FINGERPRINT",
                description = "Framework fingerprint constant",
                value = fingerprint,
                category = SystemPropertyCategory.BUILD_PROFILE,
                severity = if (matchedPattern != null) {
                    SystemPropertySeverity.WARNING
                } else {
                    SystemPropertySeverity.SAFE
                },
                source = SystemPropertySource.BUILD,
                detail = matchedPattern?.let { "Suspicious fingerprint pattern matched '$it'." }
                    ?: "Collected from android.os.Build.FINGERPRINT.",
            )
        }

        return signals
    }

    internal fun buildPropAreaSignals(
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): List<SystemPropertySignal> {
        return nativeSnapshot.propAreaFindings.map { finding ->
            SystemPropertySignal(
                property = "prop_area hole: ${finding.context}",
                description = "Raw property area layout residue",
                value = "${finding.holeCount} hole(s)",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = propAreaSeverity(finding.context),
                source = SystemPropertySource.NATIVE_LIBC,
                detail = buildString {
                    append("Context: ")
                    append(finding.context)
                    append(". ")
                    append(finding.detail.ifBlank { "Found hole in prop area: ${finding.context}" })
                    append(". Native /dev/__properties__ layout scan.")
                },
            )
        }
    }

    internal fun buildReadOnlySerialSignals(
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): List<SystemPropertySignal> {
        return nativeSnapshot.readOnlySerialFindings.map { finding ->
            SystemPropertySignal(
                property = "ro serial anomaly: ${finding.property}",
                description = "Read-only property update-serial anomaly",
                value = "low24=${finding.low24Hex}",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = readOnlySerialSeverity(finding.property),
                source = SystemPropertySource.NATIVE_LIBC,
                detail = buildString {
                    append("Property: ")
                    append(finding.property)
                    append(". Samples: ")
                    append(finding.suspiciousSampleCount)
                    append("/3 suspicious. ")
                    append(
                        finding.detail.ifBlank {
                            "Read-only property low-24 update-field anomaly detected via native libc sampling."
                        },
                    )
                },
            )
        }
    }

    internal fun buildReadOnlySerialMethod(
        readOnlySerialAvailable: Boolean,
        readOnlySerialCheckedCount: Int,
        readOnlySerialFindingCount: Int,
        readOnlySerialSignals: List<SystemPropertySignal>,
    ): SystemPropertiesMethodResult {
        return SystemPropertiesMethodResult(
            label = "Read-only serials",
            summary = when {
                !readOnlySerialAvailable -> "Unavailable"
                readOnlySerialFindingCount > 0 -> "$readOnlySerialFindingCount anomaly(s)"
                else -> "Clean"
            },
            outcome = when {
                readOnlySerialSignals.any { it.severity == SystemPropertySeverity.DANGER } -> SystemPropertiesMethodOutcome.DANGER
                readOnlySerialSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
                readOnlySerialAvailable -> SystemPropertiesMethodOutcome.CLEAN
                else -> SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = if (readOnlySerialAvailable) {
                "Sampled native libc serials for $readOnlySerialCheckedCount tracked ro.* property/properties. Per AOSP, the high 8 bits encode value length, while normal write-once ro.* properties keep the low-24 update field at zero after init; long ro.* values may carry kLongFlag."
            } else {
                "Read-only property serial sampling unavailable."
            },
        )
    }

    internal fun buildPropAreaMethod(
        propAreaAvailable: Boolean,
        propAreaContextCount: Int,
        propAreaHoleCount: Int,
        propAreaSignals: List<SystemPropertySignal>,
    ): SystemPropertiesMethodResult {
        return SystemPropertiesMethodResult(
            label = "Prop area layout",
            summary = when {
                !propAreaAvailable -> "Unavailable"
                propAreaHoleCount > 0 -> "$propAreaHoleCount hole(s)"
                else -> "Clean"
            },
            outcome = when {
                propAreaSignals.any { it.severity == SystemPropertySeverity.DANGER } -> SystemPropertiesMethodOutcome.DANGER
                propAreaSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
                propAreaAvailable -> SystemPropertiesMethodOutcome.CLEAN
                else -> SystemPropertiesMethodOutcome.SUPPORT
            },
            detail = if (propAreaAvailable) {
                "Raw /dev/__properties__ layout scan across $propAreaContextCount area(s)."
            } else {
                "Raw /dev/__properties__ layout scan unavailable."
            },
        )
    }

    private fun buildMethods(
        ruleSignals: List<SystemPropertySignal>,
        infoSignals: List<SystemPropertySignal>,
        reflectionHitCount: Int,
        getpropHitCount: Int,
        jvmHitCount: Int,
        nativeHitCount: Int,
        bootParamHitCount: Int,
        observedRuleCount: Int,
        buildSignals: List<SystemPropertySignal>,
        sourceSignals: List<SystemPropertySignal>,
        consistencySignals: List<SystemPropertySignal>,
        readOnlySerialSignals: List<SystemPropertySignal>,
        readOnlySerialAvailable: Boolean,
        readOnlySerialCheckedCount: Int,
        readOnlySerialFindingCount: Int,
        propAreaSignals: List<SystemPropertySignal>,
        propAreaAvailable: Boolean,
        propAreaContextCount: Int,
        propAreaHoleCount: Int,
    ): List<SystemPropertiesMethodResult> {
        val buildDangerCount = buildSignals.count { it.severity == SystemPropertySeverity.DANGER }
        val buildWarningCount = buildSignals.count { it.severity == SystemPropertySeverity.WARNING }
        val sourceDangerCount = sourceSignals.count { it.severity == SystemPropertySeverity.DANGER }
        val consistencyDangerCount =
            consistencySignals.count { it.severity == SystemPropertySeverity.DANGER }

        return listOf(
            SystemPropertiesMethodResult(
                label = "Reflection API",
                summary = if (reflectionHitCount > 0) "$reflectionHitCount hit(s)" else "Unavailable",
                outcome = if (reflectionHitCount > 0) {
                    SystemPropertiesMethodOutcome.CLEAN
                } else {
                    SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "android.os.SystemProperties reflection reads.",
            ),
            SystemPropertiesMethodResult(
                label = "getprop snapshot",
                summary = if (getpropHitCount > 0) "$getpropHitCount hit(s)" else "Unavailable",
                outcome = if (getpropHitCount > 0) {
                    SystemPropertiesMethodOutcome.CLEAN
                } else {
                    SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "Single getprop dump parsed once and reused for cross-checks.",
            ),
            SystemPropertiesMethodResult(
                label = "JVM property fallback",
                summary = if (jvmHitCount > 0) "$jvmHitCount fallback(s)" else "Not needed",
                outcome = if (jvmHitCount > 0) {
                    SystemPropertiesMethodOutcome.SUPPORT
                } else {
                    SystemPropertiesMethodOutcome.CLEAN
                },
                detail = "System.getProperty fallback reads.",
            ),
            SystemPropertiesMethodResult(
                label = "Native libc",
                summary = if (nativeHitCount > 0) "$nativeHitCount hit(s)" else "Unavailable",
                outcome = if (nativeHitCount > 0) {
                    SystemPropertiesMethodOutcome.CLEAN
                } else {
                    SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "Native libc property cross-checks using the callback-based system property API.",
            ),
            SystemPropertiesMethodResult(
                label = "Raw boot params",
                summary = if (bootParamHitCount > 0) "$bootParamHitCount hit(s)" else "Unavailable",
                outcome = if (bootParamHitCount > 0) {
                    SystemPropertiesMethodOutcome.CLEAN
                } else {
                    SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "androidboot.* values from /proc/cmdline and /proc/bootconfig.",
            ),
            SystemPropertiesMethodResult(
                label = "Build constants",
                summary = when {
                    buildDangerCount > 0 -> "$buildDangerCount danger"
                    buildWarningCount > 0 -> "$buildWarningCount warning"
                    buildSignals.isNotEmpty() -> "Clean"
                    else -> "Unavailable"
                },
                outcome = when {
                    buildDangerCount > 0 -> SystemPropertiesMethodOutcome.DANGER
                    buildWarningCount > 0 -> SystemPropertiesMethodOutcome.WARNING
                    buildSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.CLEAN
                    else -> SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "Build.TYPE, Build.TAGS, and Build.FINGERPRINT checks.",
            ),
            SystemPropertiesMethodResult(
                label = "Source consistency",
                summary = when {
                    sourceDangerCount > 0 -> "$sourceDangerCount danger"
                    sourceSignals.isNotEmpty() -> "${sourceSignals.size} mismatch(es)"
                    else -> "Aligned"
                },
                outcome = when {
                    sourceDangerCount > 0 -> SystemPropertiesMethodOutcome.DANGER
                    sourceSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
                    nativeHitCount > 0 || reflectionHitCount > 0 || getpropHitCount > 0 -> SystemPropertiesMethodOutcome.CLEAN
                    else -> SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "Cross-source comparison across reflection, getprop, JVM, and native libc reads.",
            ),
            SystemPropertiesMethodResult(
                label = "Cross-check rules",
                summary = when {
                    consistencyDangerCount > 0 -> "$consistencyDangerCount danger"
                    consistencySignals.isNotEmpty() -> "${consistencySignals.size} warning(s)"
                    else -> "Aligned"
                },
                outcome = when {
                    consistencyDangerCount > 0 -> SystemPropertiesMethodOutcome.DANGER
                    consistencySignals.isNotEmpty() -> SystemPropertiesMethodOutcome.WARNING
                    else -> SystemPropertiesMethodOutcome.CLEAN
                },
                detail = "Framework-vs-property, fingerprint-tail, raw-boot, and lock-state coherence checks.",
            ),
            buildReadOnlySerialMethod(
                readOnlySerialAvailable = readOnlySerialAvailable,
                readOnlySerialCheckedCount = readOnlySerialCheckedCount,
                readOnlySerialFindingCount = readOnlySerialFindingCount,
                readOnlySerialSignals = readOnlySerialSignals,
            ),
            buildPropAreaMethod(
                propAreaAvailable = propAreaAvailable,
                propAreaContextCount = propAreaContextCount,
                propAreaHoleCount = propAreaHoleCount,
                propAreaSignals = propAreaSignals,
            ),
            SystemPropertiesMethodResult(
                label = "Property catalog",
                summary = "$observedRuleCount / ${SystemPropertiesCatalog.rules.size} observed",
                outcome = when {
                    ruleSignals.any { it.severity == SystemPropertySeverity.DANGER } -> SystemPropertiesMethodOutcome.DANGER
                    ruleSignals.any { it.severity == SystemPropertySeverity.WARNING } -> SystemPropertiesMethodOutcome.WARNING
                    observedRuleCount > 0 || infoSignals.isNotEmpty() -> SystemPropertiesMethodOutcome.CLEAN
                    else -> SystemPropertiesMethodOutcome.SUPPORT
                },
                detail = "Security rule matches plus ${infoSignals.size} info-only properties.",
            ),
        )
    }

    private fun matchesDanger(
        rule: SystemPropertyRule,
        value: String,
    ): Boolean {
        if (rule.dangerousValues.contains("*") && value.isNotBlank()) {
            return true
        }
        return rule.dangerousValues.any { danger ->
            danger.equals(value, ignoreCase = true)
        }
    }

    private fun matchesWarning(
        rule: SystemPropertyRule,
        value: String,
    ): Boolean {
        return rule.warningValues.any { warning ->
            warning.equals(value, ignoreCase = true)
        }
    }

    private fun infoCategory(
        property: String,
    ): SystemPropertyCategory {
        return if (property.contains("fingerprint", ignoreCase = true)) {
            SystemPropertyCategory.BUILD_FINGERPRINT
        } else {
            SystemPropertyCategory.DEVICE_INFO
        }
    }

    private fun friendlyInfoLabel(
        property: String,
    ): String {
        return when (property) {
            "ro.build.fingerprint" -> "System fingerprint"
            "ro.bootimage.build.fingerprint" -> "Boot image fingerprint"
            "ro.vendor.build.fingerprint" -> "Vendor fingerprint"
            "ro.system.build.fingerprint" -> "System partition fingerprint"
            "ro.build.display.id" -> "Build display ID"
            "ro.build.version.release" -> "Android version"
            "ro.build.version.sdk" -> "SDK level"
            "ro.build.version.security_patch" -> "Security patch"
            "ro.product.model" -> "Model"
            "ro.product.brand" -> "Brand"
            "ro.product.device" -> "Device codename"
            "ro.product.manufacturer" -> "Manufacturer"
            "ro.hardware" -> "Hardware"
            "ro.boot.vbmeta.hash_alg" -> "VBMeta hash algorithm"
            "ro.boot.vbmeta.size" -> "VBMeta size"
            "ro.boot.vbmeta.digest" -> "VBMeta digest"
            "ro.boot.avb_version" -> "AVB version"
            else -> property
        }
    }

    private fun sourceLabel(
        source: SystemPropertySource,
    ): String {
        return when (source) {
            SystemPropertySource.REFLECTION -> "reflection"
            SystemPropertySource.GETPROP -> "getprop"
            SystemPropertySource.JVM -> "System.getProperty"
            SystemPropertySource.BUILD -> "Build constant"
            SystemPropertySource.NATIVE_LIBC -> "native libc"
            SystemPropertySource.CMDLINE -> "/proc/cmdline"
            SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
        }
    }

    private companion object {
        private const val SERVICE_ADB_ROOT = "service.adb.root"

        private fun propAreaSeverity(context: String): SystemPropertySeverity {
            val lowered = context.lowercase()
            return if ("adbd_config_prop" in lowered || "shell_prop" in lowered) {
                SystemPropertySeverity.DANGER
            } else {
                SystemPropertySeverity.WARNING
            }
        }

        private fun readOnlySerialSeverity(property: String): SystemPropertySeverity {
            val lowered = property.lowercase()
            return if (
                lowered.startsWith("ro.boot.") ||
                lowered.startsWith("ro.build.") ||
                lowered.startsWith("ro.vendor.") ||
                lowered.startsWith("ro.system.") ||
                lowered.startsWith("ro.product.") ||
                lowered == "ro.secure" ||
                lowered == "ro.debuggable" ||
                lowered == "ro.adb.secure" ||
                lowered == "ro.build.selinux" ||
                lowered == "ro.crypto.state"
            ) {
                SystemPropertySeverity.DANGER
            } else {
                SystemPropertySeverity.WARNING
            }
        }
    }
}
