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

package com.eltavine.duckdetector.features.playintegrityfix.data.repository

import com.eltavine.duckdetector.features.playintegrityfix.data.rules.PlayIntegrityFixCatalog
import com.eltavine.duckdetector.features.playintegrityfix.data.utils.PlayIntegrityConsistencyUtils
import com.eltavine.duckdetector.features.playintegrityfix.data.utils.PlayIntegrityMultiSourceRead
import com.eltavine.duckdetector.features.playintegrityfix.data.utils.PlayIntegrityPropertyReadUtils
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixGroup
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixMethodOutcome
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixMethodResult
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixPropertyCategory
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixReport
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignal
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignalSeverity
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSource
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixStage
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class PlayIntegrityFixRepository(
    private val readUtils: PlayIntegrityPropertyReadUtils = PlayIntegrityPropertyReadUtils(),
    private val consistencyUtils: PlayIntegrityConsistencyUtils = PlayIntegrityConsistencyUtils(),
) {

    suspend fun scan(): PlayIntegrityFixReport = withContext(Dispatchers.IO) {
        runCatching { scanInternal() }
            .getOrElse { throwable ->
                PlayIntegrityFixReport.failed(
                    throwable.message ?: "Play Integrity Fix scan failed."
                )
            }
    }

    private fun scanInternal(): PlayIntegrityFixReport {
        val nativeSnapshot =
            readUtils.collectNativeSnapshot(PlayIntegrityFixCatalog.rules.map { it.property })
        val cache = linkedMapOf<String, PlayIntegrityMultiSourceRead>()
        val propertySignals = PlayIntegrityFixCatalog.rules.mapNotNull { rule ->
            val read = readUtils.readProperty(rule, cache, nativeSnapshot)
            if (read.preferredValue.isBlank()) {
                return@mapNotNull null
            }
            buildPropertySignal(read)
        }
        val consistencySignals = consistencyUtils.buildSourceMismatchSignals(cache.values)
        val nativeSignals = nativeSnapshot.runtimeTraces.mapIndexed { index, trace ->
            PlayIntegrityFixSignal(
                id = "native_$index",
                label = trace.label,
                value = if (trace.severity == "DANGER") "Danger" else "Review",
                group = PlayIntegrityFixGroup.NATIVE,
                category = PlayIntegrityFixPropertyCategory.RUNTIME,
                severity = if (trace.severity == "DANGER") {
                    PlayIntegrityFixSignalSeverity.DANGER
                } else {
                    PlayIntegrityFixSignalSeverity.WARNING
                },
                source = PlayIntegrityFixSource.NATIVE_MAPS,
                detail = trace.detail,
                detailMonospace = true,
            )
        }

        val reflectionHitCount = cache.values.count {
            it.sourceValues[PlayIntegrityFixSource.REFLECTION].isNullOrBlank().not()
        }
        val getpropHitCount = cache.values.count {
            it.sourceValues[PlayIntegrityFixSource.GETPROP].isNullOrBlank().not()
        }
        val jvmHitCount = cache.values.count {
            it.sourceValues[PlayIntegrityFixSource.JVM].isNullOrBlank().not()
        }

        return PlayIntegrityFixReport(
            stage = PlayIntegrityFixStage.READY,
            propertySignals = propertySignals,
            consistencySignals = consistencySignals,
            nativeSignals = nativeSignals,
            checkedPropertyCount = PlayIntegrityFixCatalog.rules.size,
            reflectionHitCount = reflectionHitCount,
            getpropHitCount = getpropHitCount,
            jvmHitCount = jvmHitCount,
            nativePropertyHitCount = nativeSnapshot.nativePropertyHitCount,
            nativeTraceCount = nativeSnapshot.runtimeTraces.size,
            nativeAvailable = nativeSnapshot.available,
            methods = buildMethods(
                propertySignals = propertySignals,
                consistencySignals = consistencySignals,
                nativeSignals = nativeSignals,
                reflectionHitCount = reflectionHitCount,
                getpropHitCount = getpropHitCount,
                jvmHitCount = jvmHitCount,
                nativeHitCount = nativeSnapshot.nativePropertyHitCount,
                nativeTraceCount = nativeSnapshot.runtimeTraces.size,
                nativeAvailable = nativeSnapshot.available,
            ),
        )
    }

    private fun buildPropertySignal(
        read: PlayIntegrityMultiSourceRead,
    ): PlayIntegrityFixSignal {
        val normalized = read.preferredValue.trim().lowercase()
        val severity = if (normalized in DISABLED_VALUES) {
            PlayIntegrityFixSignalSeverity.WARNING
        } else {
            PlayIntegrityFixSignalSeverity.DANGER
        }
        val nonBlankSourceCount = read.sourceValues.count { it.value.isNotBlank() }
        return PlayIntegrityFixSignal(
            id = read.rule.property,
            label = read.rule.label,
            value = badgeValue(read.preferredValue),
            group = PlayIntegrityFixGroup.PROPERTIES,
            category = read.rule.category,
            severity = severity,
            source = read.preferredSource,
            detail = buildString {
                append(read.rule.property)
                append('\n')
                append("Preferred source: ")
                append(read.preferredSource.label)
                append('\n')
                append("Value: ")
                append(read.preferredValue)
                if (nonBlankSourceCount > 1) {
                    append('\n')
                    append("Non-empty sources: ")
                    append(nonBlankSourceCount)
                }
            },
            detailMonospace = true,
        )
    }

    private fun buildMethods(
        propertySignals: List<PlayIntegrityFixSignal>,
        consistencySignals: List<PlayIntegrityFixSignal>,
        nativeSignals: List<PlayIntegrityFixSignal>,
        reflectionHitCount: Int,
        getpropHitCount: Int,
        jvmHitCount: Int,
        nativeHitCount: Int,
        nativeTraceCount: Int,
        nativeAvailable: Boolean,
    ): List<PlayIntegrityFixMethodResult> {
        return listOf(
            PlayIntegrityFixMethodResult(
                label = "Reflection API",
                summary = if (reflectionHitCount > 0) "$reflectionHitCount hit(s)" else "Unavailable",
                outcome = if (reflectionHitCount > 0) PlayIntegrityFixMethodOutcome.CLEAN else PlayIntegrityFixMethodOutcome.SUPPORT,
                detail = "android.os.SystemProperties reflection reads for PIF residue properties.",
            ),
            PlayIntegrityFixMethodResult(
                label = "getprop snapshot",
                summary = if (getpropHitCount > 0) "$getpropHitCount hit(s)" else "Unavailable",
                outcome = if (getpropHitCount > 0) PlayIntegrityFixMethodOutcome.CLEAN else PlayIntegrityFixMethodOutcome.SUPPORT,
                detail = "Single getprop dump reused for all PIF property checks.",
            ),
            PlayIntegrityFixMethodResult(
                label = "JVM fallback",
                summary = if (jvmHitCount > 0) "$jvmHitCount fallback(s)" else "Not needed",
                outcome = if (jvmHitCount > 0) PlayIntegrityFixMethodOutcome.SUPPORT else PlayIntegrityFixMethodOutcome.CLEAN,
                detail = "System.getProperty fallback, mainly useful as a weak consistency source.",
            ),
            PlayIntegrityFixMethodResult(
                label = "Native libc props",
                summary = if (nativeHitCount > 0) "$nativeHitCount hit(s)" else if (nativeAvailable) "Clean" else "Unavailable",
                outcome = when {
                    nativeHitCount > 0 -> PlayIntegrityFixMethodOutcome.DETECTED
                    nativeAvailable -> PlayIntegrityFixMethodOutcome.CLEAN
                    else -> PlayIntegrityFixMethodOutcome.SUPPORT
                },
                detail = "__system_property_get checks for PIF-specific persist.sys residue.",
            ),
            PlayIntegrityFixMethodResult(
                label = "Native maps",
                summary = if (nativeTraceCount > 0) "$nativeTraceCount trace(s)" else if (nativeAvailable) "Clean" else "Unavailable",
                outcome = when {
                    nativeSignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> PlayIntegrityFixMethodOutcome.DETECTED
                    nativeSignals.isNotEmpty() -> PlayIntegrityFixMethodOutcome.WARNING
                    nativeAvailable -> PlayIntegrityFixMethodOutcome.CLEAN
                    else -> PlayIntegrityFixMethodOutcome.SUPPORT
                },
                detail = "Scans current-process memory maps for playintegrity/pihooks/pixelprops/keystore-related runtime traces.",
            ),
            PlayIntegrityFixMethodResult(
                label = "Property catalog",
                summary = if (propertySignals.isNotEmpty()) "${propertySignals.size} hit(s)" else "Clean",
                outcome = when {
                    propertySignals.any { it.severity == PlayIntegrityFixSignalSeverity.DANGER } -> PlayIntegrityFixMethodOutcome.DETECTED
                    propertySignals.isNotEmpty() -> PlayIntegrityFixMethodOutcome.WARNING
                    else -> PlayIntegrityFixMethodOutcome.CLEAN
                },
                detail = "Checks PIF control, Pixel props, spoofed device identity, and security patch residue properties.",
            ),
            PlayIntegrityFixMethodResult(
                label = "Source consistency",
                summary = if (consistencySignals.isNotEmpty()) "${consistencySignals.size} mismatch(es)" else "Aligned",
                outcome = if (consistencySignals.isNotEmpty()) {
                    PlayIntegrityFixMethodOutcome.WARNING
                } else {
                    PlayIntegrityFixMethodOutcome.CLEAN
                },
                detail = "Flags cases where reflection, getprop, JVM, and native libc disagree for the same PIF residue property.",
            ),
        )
    }

    private fun badgeValue(value: String): String {
        val trimmed = value.trim()
        return if (trimmed.length > 18) "Set" else trimmed
    }

    private companion object {
        private val DISABLED_VALUES = setOf("0", "false", "off", "disabled", "none")
    }
}
