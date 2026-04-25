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

package com.eltavine.duckdetector.features.systemproperties.data.utils

import android.os.Build
import com.eltavine.duckdetector.features.systemproperties.data.native.SystemPropertiesNativeSnapshot
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySeverity
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySignal
import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertySource

class SystemPropertyConsistencyUtils {

    fun buildSourceMismatchSignals(
        reads: Collection<MultiSourcePropertyRead>,
    ): List<SystemPropertySignal> {
        return reads.mapNotNull { read ->
            if (!shouldEvaluateSourceMismatch(read.category)) {
                return@mapNotNull null
            }
            val populatedSources = read.sourceValues
                .mapValues { (_, value) -> sanitizeSourceValue(value) }
                .filterValues { it.isNotBlank() }
            val normalizedDistinct = populatedSources.values
                .map { normalizeForComparison(read.property, it) }
                .distinct()
            if (normalizedDistinct.size <= 1) {
                return@mapNotNull null
            }

            val severity = when {
                populatedSources.containsKey(SystemPropertySource.NATIVE_LIBC) &&
                        read.property in criticalSourceMismatchProperties -> SystemPropertySeverity.DANGER

                read.property.startsWith("ro.boot.") &&
                        populatedSources.containsKey(SystemPropertySource.NATIVE_LIBC) -> SystemPropertySeverity.DANGER

                else -> SystemPropertySeverity.WARNING
            }

            SystemPropertySignal(
                property = read.property,
                description = "Property source mismatch",
                value = "Diverged",
                category = SystemPropertyCategory.SOURCE_CONSISTENCY,
                severity = severity,
                source = read.preferredSource,
                detail = populatedSources.entries
                    .sortedBy { sourcePriority(it.key) }
                    .joinToString(separator = "\n") { (source, value) ->
                        "${sourceLabel(source)}: $value"
                    },
            )
        }
    }

    fun buildConsistencySignals(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): List<SystemPropertySignal> {
        return buildList {
            addAll(buildRawBootSignals(readsByProperty, nativeSnapshot))
            addAll(buildFrameworkConsistencySignals(readsByProperty))
            addAll(buildBuildFingerprintTailSignals(readsByProperty))
            buildVerifiedBootLockSignal(readsByProperty)?.let(::add)
            buildUserBuildDebugSignal(readsByProperty)?.let(::add)
            buildPartitionVerificationSignal(readsByProperty)?.let(::add)
        }
    }

    private fun buildRawBootSignals(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
        nativeSnapshot: SystemPropertiesNativeSnapshot,
    ): List<SystemPropertySignal> {
        return trackedRawBootProperties.mapNotNull { property ->
            val read = readsByProperty[property] ?: return@mapNotNull null
            val propertyValue = read.preferredValue
            if (propertyValue.isBlank()) {
                return@mapNotNull null
            }
            val (bootSource, rawValue) = nativeSnapshot.findBootValueForProperty(property)
                ?: return@mapNotNull null
            if (normalizeForComparison(property, propertyValue) == normalizeForComparison(
                    property,
                    rawValue
                )
            ) {
                return@mapNotNull null
            }

            SystemPropertySignal(
                property = "$property <> ${bootSourceLabel(bootSource)}",
                description = "Android property disagrees with raw boot parameter",
                value = "Contradiction",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = SystemPropertySeverity.DANGER,
                source = bootSource,
                detail = buildString {
                    append(property)
                    append(" via ")
                    append(sourceLabel(read.preferredSource))
                    append(" = ")
                    append(propertyValue)
                    appendLine()
                    append(bootSourceLabel(bootSource))
                    append(" = ")
                    append(rawValue)
                },
            )
        }
    }

    private fun buildFrameworkConsistencySignals(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): List<SystemPropertySignal> {
        val findings = mutableListOf<SystemPropertySignal>()

        compareFrameworkAndProperty(
            propertyName = "ro.build.type",
            frameworkValue = Build.TYPE.orEmpty(),
            frameworkLabel = "Build.TYPE",
            readsByProperty = readsByProperty,
        )?.let(findings::add)

        compareFrameworkAndProperty(
            propertyName = "ro.build.tags",
            frameworkValue = Build.TAGS.orEmpty(),
            frameworkLabel = "Build.TAGS",
            readsByProperty = readsByProperty,
        )?.let(findings::add)

        compareFrameworkAndProperty(
            propertyName = "ro.build.fingerprint",
            frameworkValue = Build.FINGERPRINT.orEmpty(),
            frameworkLabel = "Build.FINGERPRINT",
            readsByProperty = readsByProperty,
        )?.let(findings::add)

        return findings
    }

    private fun buildBuildFingerprintTailSignals(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): List<SystemPropertySignal> {
        val parsed = parseBuildFingerprint(Build.FINGERPRINT.orEmpty()) ?: return emptyList()
        val findings = mutableListOf<SystemPropertySignal>()

        if (normalizeForComparison(
                "Build.TYPE",
                Build.TYPE.orEmpty()
            ) != normalizeForComparison("Build.TYPE", parsed.type)
        ) {
            findings += SystemPropertySignal(
                property = "Build.TYPE <> fingerprint tail",
                description = "Build type disagrees with fingerprint format tail",
                value = "Type drift",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = SystemPropertySeverity.WARNING,
                source = SystemPropertySource.BUILD,
                detail = "Build.TYPE=${Build.TYPE.orEmpty()}\nFingerprint type=${parsed.type}",
            )
        }

        if (normalizeForComparison(
                "Build.TAGS",
                Build.TAGS.orEmpty()
            ) != normalizeForComparison("Build.TAGS", parsed.tags)
        ) {
            findings += SystemPropertySignal(
                property = "Build.TAGS <> fingerprint tail",
                description = "Build tags disagree with fingerprint format tail",
                value = "Tags drift",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = SystemPropertySeverity.WARNING,
                source = SystemPropertySource.BUILD,
                detail = "Build.TAGS=${Build.TAGS.orEmpty()}\nFingerprint tags=${parsed.tags}",
            )
        }

        val roBuildType = readsByProperty["ro.build.type"]?.preferredValue.orEmpty()
        if (roBuildType.isNotBlank() &&
            normalizeForComparison(
                "ro.build.type",
                roBuildType
            ) != normalizeForComparison("ro.build.type", parsed.type)
        ) {
            findings += SystemPropertySignal(
                property = "ro.build.type <> fingerprint tail",
                description = "ro.build.type disagrees with fingerprint format tail",
                value = "Type drift",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = SystemPropertySeverity.WARNING,
                source = readsByProperty["ro.build.type"]?.preferredSource
                    ?: SystemPropertySource.REFLECTION,
                detail = "ro.build.type=$roBuildType\nFingerprint type=${parsed.type}",
            )
        }

        val roBuildTags = readsByProperty["ro.build.tags"]?.preferredValue.orEmpty()
        if (roBuildTags.isNotBlank() &&
            normalizeForComparison(
                "ro.build.tags",
                roBuildTags
            ) != normalizeForComparison("ro.build.tags", parsed.tags)
        ) {
            findings += SystemPropertySignal(
                property = "ro.build.tags <> fingerprint tail",
                description = "ro.build.tags disagrees with fingerprint format tail",
                value = "Tags drift",
                category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
                severity = SystemPropertySeverity.WARNING,
                source = readsByProperty["ro.build.tags"]?.preferredSource
                    ?: SystemPropertySource.REFLECTION,
                detail = "ro.build.tags=$roBuildTags\nFingerprint tags=${parsed.tags}",
            )
        }

        return findings
    }

    private fun buildVerifiedBootLockSignal(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): SystemPropertySignal? {
        val verifiedBootState =
            readsByProperty["ro.boot.verifiedbootstate"]?.preferredValue.orEmpty()
        val flashLocked = readsByProperty["ro.boot.flash.locked"]?.preferredValue.orEmpty()
        val vbmetaState = readsByProperty["ro.boot.vbmeta.device_state"]?.preferredValue.orEmpty()
        if (verifiedBootState.isBlank()) {
            return null
        }

        val contradiction = when {
            verifiedBootState.equals("green", ignoreCase = true) ||
                    verifiedBootState.equals("yellow", ignoreCase = true) -> {
                isUnlockedValue(flashLocked) || vbmetaState.equals("unlocked", ignoreCase = true)
            }

            verifiedBootState.equals("orange", ignoreCase = true) -> {
                isLockedValue(flashLocked) || vbmetaState.equals("locked", ignoreCase = true)
            }

            else -> false
        }

        if (!contradiction) {
            return null
        }

        return SystemPropertySignal(
            property = "Verified boot coherence",
            description = "Verified boot state conflicts with lock state",
            value = "Contradiction",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.DANGER,
            source = readsByProperty["ro.boot.verifiedbootstate"]?.preferredSource
                ?: SystemPropertySource.REFLECTION,
            detail = "ro.boot.verifiedbootstate=$verifiedBootState\nro.boot.flash.locked=$flashLocked\nro.boot.vbmeta.device_state=$vbmetaState",
        )
    }

    private fun buildUserBuildDebugSignal(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): SystemPropertySignal? {
        val buildType = readsByProperty["ro.build.type"]?.preferredValue
            ?.takeIf { it.isNotBlank() }
            ?: Build.TYPE.orEmpty()
        val debuggable = readsByProperty["ro.debuggable"]?.preferredValue.orEmpty()
        if (!buildType.equals("user", ignoreCase = true) || debuggable != "1") {
            return null
        }

        return SystemPropertySignal(
            property = "Build profile coherence",
            description = "user build reports ro.debuggable=1",
            value = "Contradiction",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.DANGER,
            source = readsByProperty["ro.debuggable"]?.preferredSource
                ?: SystemPropertySource.REFLECTION,
            detail = "Effective build type=$buildType\nro.debuggable=$debuggable",
        )
    }

    private fun buildPartitionVerificationSignal(
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): SystemPropertySignal? {
        val verifiedBootState =
            readsByProperty["ro.boot.verifiedbootstate"]?.preferredValue.orEmpty()
        if (!verifiedBootState.equals("green", ignoreCase = true) &&
            !verifiedBootState.equals("yellow", ignoreCase = true)
        ) {
            return null
        }

        val disabled = partitionVerifiedProperties.filter { property ->
            readsByProperty[property]?.preferredValue == "0"
        }
        val logging = partitionVerifiedProperties.filter { property ->
            readsByProperty[property]?.preferredValue == "2"
        }
        if (disabled.isEmpty() && logging.isEmpty()) {
            return null
        }

        val severity = if (disabled.isNotEmpty()) {
            SystemPropertySeverity.DANGER
        } else {
            SystemPropertySeverity.WARNING
        }

        return SystemPropertySignal(
            property = "Partition verification coherence",
            description = "Verified boot state conflicts with partition dm-verity flags",
            value = if (disabled.isNotEmpty()) "Disabled" else "Logging",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = severity,
            source = readsByProperty["ro.boot.verifiedbootstate"]?.preferredSource
                ?: SystemPropertySource.REFLECTION,
            detail = buildString {
                append("ro.boot.verifiedbootstate=")
                append(verifiedBootState)
                if (disabled.isNotEmpty()) {
                    appendLine()
                    append("Disabled partitions: ")
                    append(disabled.joinToString())
                }
                if (logging.isNotEmpty()) {
                    appendLine()
                    append("Logging partitions: ")
                    append(logging.joinToString())
                }
            },
        )
    }

    private fun compareFrameworkAndProperty(
        propertyName: String,
        frameworkValue: String,
        frameworkLabel: String,
        readsByProperty: Map<String, MultiSourcePropertyRead>,
    ): SystemPropertySignal? {
        val read = readsByProperty[propertyName] ?: return null
        val propertyValue = read.preferredValue
        if (frameworkValue.isBlank() || propertyValue.isBlank()) {
            return null
        }
        if (normalizeForComparison(propertyName, propertyValue) == normalizeForComparison(
                propertyName,
                frameworkValue
            )
        ) {
            return null
        }
        return SystemPropertySignal(
            property = "$propertyName <> $frameworkLabel",
            description = "Framework constant disagrees with system property",
            value = "Drift",
            category = SystemPropertyCategory.PROPERTY_CONSISTENCY,
            severity = SystemPropertySeverity.WARNING,
            source = SystemPropertySource.BUILD,
            detail = "$propertyName=$propertyValue\n$frameworkLabel=$frameworkValue",
        )
    }

    private fun shouldEvaluateSourceMismatch(
        category: SystemPropertyCategory,
    ): Boolean {
        return category != SystemPropertyCategory.DEVICE_INFO
    }

    private fun parseBuildFingerprint(
        fingerprint: String,
    ): ParsedBuildFingerprint? {
        if (fingerprint.isBlank()) {
            return null
        }
        val tail = fingerprint.substringAfterLast(':', missingDelimiterValue = "")
        if (tail.isBlank() || !tail.contains('/')) {
            return null
        }
        return ParsedBuildFingerprint(
            type = tail.substringBefore('/').trim(),
            tags = tail.substringAfter('/').trim(),
        )
    }

    private fun normalizeForComparison(
        property: String,
        value: String,
    ): String {
        val normalized = value.trim().lowercase()
        return if (property in booleanStyleProperties) {
            when (normalized) {
                "1", "true", "locked", "yes" -> "true"
                "0", "false", "unlocked", "no" -> "false"
                else -> normalized
            }
        } else {
            normalized
        }
    }

    private fun sanitizeSourceValue(
        value: String,
    ): String {
        val trimmed = value.trim()
        return if (trimmed.contains(CALLBACK_REQUIRED_MESSAGE, ignoreCase = true)) {
            ""
        } else {
            trimmed
        }
    }

    private fun isUnlockedValue(
        value: String,
    ): Boolean {
        return normalizeForComparison("lock", value) == "false"
    }

    private fun isLockedValue(
        value: String,
    ): Boolean {
        return normalizeForComparison("lock", value) == "true"
    }

    private fun sourcePriority(
        source: SystemPropertySource,
    ): Int {
        return when (source) {
            SystemPropertySource.REFLECTION -> 0
            SystemPropertySource.GETPROP -> 1
            SystemPropertySource.NATIVE_LIBC -> 2
            SystemPropertySource.JVM -> 3
            SystemPropertySource.BUILD -> 4
            SystemPropertySource.BOOTCONFIG -> 5
            SystemPropertySource.CMDLINE -> 6
        }
    }

    private fun sourceLabel(
        source: SystemPropertySource,
    ): String {
        return when (source) {
            SystemPropertySource.REFLECTION -> "Reflection"
            SystemPropertySource.GETPROP -> "getprop"
            SystemPropertySource.JVM -> "System.getProperty"
            SystemPropertySource.BUILD -> "Build constant"
            SystemPropertySource.NATIVE_LIBC -> "Native libc"
            SystemPropertySource.CMDLINE -> "/proc/cmdline"
            SystemPropertySource.BOOTCONFIG -> "/proc/bootconfig"
        }
    }

    private fun bootSourceLabel(
        source: SystemPropertySource,
    ): String {
        return when (source) {
            SystemPropertySource.BOOTCONFIG -> "androidboot.* from /proc/bootconfig"
            SystemPropertySource.CMDLINE -> "androidboot.* from /proc/cmdline"
            else -> sourceLabel(source)
        }
    }

    private data class ParsedBuildFingerprint(
        val type: String,
        val tags: String,
    )

    private companion object {
        private val criticalSourceMismatchProperties = setOf(
            "ro.secure",
            "ro.debuggable",
            "ro.adb.secure",
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
            "ro.build.type",
            "ro.build.tags",
        )

        private val booleanStyleProperties = setOf(
            "ro.boot.flash.locked",
            "sys.oem_unlock_allowed",
            "ro.oem_unlock_supported",
            "ro.magisk.hide",
            "ro.allow.mock.location",
            "lock",
        )

        private val trackedRawBootProperties = listOf(
            "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked",
            "ro.boot.vbmeta.device_state",
        )

        private const val CALLBACK_REQUIRED_MESSAGE =
            "Must use __system_property_read_callback() to read"

        private val partitionVerifiedProperties = listOf(
            "partition.system.verified",
            "partition.vendor.verified",
            "partition.product.verified",
            "partition.system_ext.verified",
            "partition.odm.verified",
        )
    }
}
