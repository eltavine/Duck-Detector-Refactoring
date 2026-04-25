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

import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity

data class LSPosedClassProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedClassProbe {

    fun run(): LSPosedClassProbeResult {
        val signals = mutableListOf<LSPosedSignal>()
        var hitCount = 0
        val hiddenErrors = linkedSetOf<String>()
        val candidateLoaders = linkedSetOf<ClassLoader?>(
            javaClass.classLoader,
            Thread.currentThread().contextClassLoader,
            null,
        )

        CLASS_FAMILIES.forEach { family ->
            val hits = mutableListOf<String>()
            family.classNames.forEach { className ->
                var loaded = false
                candidateLoaders.forEach { loader ->
                    if (loaded) {
                        return@forEach
                    }
                    try {
                        Class.forName(className, false, loader)
                        hits += className
                        loaded = true
                    } catch (_: ClassNotFoundException) {
                        Unit
                    } catch (throwable: Throwable) {
                        throwable.message
                            ?.takeIf { containsFrameworkToken(it) }
                            ?.let { hiddenErrors += "$className -> $it" }
                    }
                }
            }

            if (hits.isNotEmpty()) {
                hitCount += hits.size
                signals += LSPosedSignal(
                    id = "class_${family.id}",
                    label = family.label,
                    value = "Loaded",
                    group = LSPosedSignalGroup.RUNTIME,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = hits.joinToString(separator = "\n"),
                    detailMonospace = true,
                )
            }
        }

        if (hiddenErrors.isNotEmpty()) {
            signals += LSPosedSignal(
                id = "class_hidden_errors",
                label = "Class loading anomalies",
                value = "Review",
                group = LSPosedSignalGroup.RUNTIME,
                severity = LSPosedSignalSeverity.WARNING,
                detail = hiddenErrors.joinToString(separator = "\n"),
                detailMonospace = true,
            )
        }

        return LSPosedClassProbeResult(
            signals = signals,
            hitCount = hitCount,
        )
    }

    private fun containsFrameworkToken(message: String): Boolean {
        val lower = message.lowercase()
        return FRAMEWORK_TOKENS.any { token -> lower.contains(token) }
    }

    private data class ClassFamily(
        val id: String,
        val label: String,
        val classNames: List<String>,
    )

    private companion object {
        private val FRAMEWORK_TOKENS = listOf(
            "lsposed",
            "xposed",
            "lspd",
            "lspatch",
            "libxposed",
        )

        private val CLASS_FAMILIES = listOf(
            ClassFamily(
                id = "legacy_api",
                label = "Legacy Xposed API",
                classNames = listOf(
                    "de.robv.android.xposed.XposedBridge",
                    "de.robv.android.xposed.XposedHelpers",
                    "de.robv.android.xposed.XC_MethodHook",
                    "de.robv.android.xposed.XC_MethodReplacement",
                    "de.robv.android.xposed.XSharedPreferences",
                    "de.robv.android.xposed.callbacks.XC_LoadPackage",
                ),
            ),
            ClassFamily(
                id = "libxposed_api",
                label = "libXposed API",
                classNames = listOf(
                    "io.github.libxposed.api.XposedInterface",
                    "io.github.libxposed.api.XposedModule",
                    "io.github.libxposed.api.XposedModuleInterface",
                ),
            ),
            ClassFamily(
                id = "lsposed_runtime",
                label = "LSPosed service classes",
                classNames = listOf(
                    "org.lsposed.lspd.core.Main",
                    "org.lsposed.lspd.service.LSPosedService",
                ),
            ),
        )
    }
}
