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

package com.eltavine.duckdetector.features.virtualization.data.probes

import android.content.Context
import dalvik.system.BaseDexClassLoader
import com.eltavine.duckdetector.features.virtualization.data.rules.VirtualizationHostAppsCatalog
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity
import java.io.File
import java.lang.reflect.Field

data class DexPathProbeResult(
    val classPathEntries: List<String> = emptyList(),
    val entryCount: Int = 0,
    val hitCount: Int = 0,
    val signals: List<VirtualizationSignal> = emptyList(),
    val sourceDir: String = "",
    val splitSourceDirs: List<String> = emptyList(),
    val hostPathHit: Boolean = false,
)

open class DexPathProbe(
    private val context: Context? = null,
    private val classLoaderProvider: () -> ClassLoader? = {
        context?.applicationContext?.classLoader ?: Thread.currentThread().contextClassLoader
    },
) {

    open fun probe(): DexPathProbeResult {
        val appContext = context?.applicationContext ?: return DexPathProbeResult()
        val sourceDir = runCatching { appContext.applicationInfo.sourceDir }.getOrDefault("")
        val splitSourceDirs = runCatching {
            appContext.applicationInfo.splitSourceDirs?.toList().orEmpty()
        }.getOrDefault(emptyList())

        val entries = collectClassPathEntries(classLoaderProvider())
        return evaluate(
            entries = entries,
            sourceDir = sourceDir,
            splitSourceDirs = splitSourceDirs,
            packageName = appContext.packageName,
        )
    }

    internal fun evaluate(
        entries: List<String>,
        sourceDir: String,
        splitSourceDirs: List<String>,
        packageName: String,
    ): DexPathProbeResult {
        val normalizedEntries = entries
            .map(::normalizePath)
            .filter { it.isNotBlank() }
            .filterNot(::isSystemPath)
            .filterNot { isOwnOverlayPath(it, packageName) }
            .distinct()
        val ownPaths = buildSet {
            normalizePath(sourceDir).takeIf { it.isNotBlank() }?.let(::add)
            splitSourceDirs.map(::normalizePath)
                .filter { it.isNotBlank() }
                .forEach(::add)
        }
        val hostSignals = mutableListOf<VirtualizationSignal>()
        val prependSignals = mutableListOf<VirtualizationSignal>()
        val otherUnexpectedEntries = mutableListOf<String>()

        val firstOwnIndex = normalizedEntries.indexOfFirst { it in ownPaths }
        normalizedEntries.forEachIndexed { index, entry ->
            if (entry in ownPaths) {
                return@forEachIndexed
            }
            val hostTarget = VirtualizationHostAppsCatalog.findHostPackageInText(entry)
            if (hostTarget != null || VirtualizationHostAppsCatalog.containsHostToken(entry)) {
                val displayValue = hostTarget?.appName ?: "Host token"
                hostSignals += VirtualizationSignal(
                    id = "virt_dex_host_${entry.stableId()}",
                    label = "Host dex path",
                    value = displayValue,
                    group = VirtualizationSignalGroup.RUNTIME,
                    severity = VirtualizationSignalSeverity.DANGER,
                    detail = entry,
                    detailMonospace = true,
                )
                return@forEachIndexed
            }

            val looksLikeDexContainer = entry.endsWith(".apk") ||
                    entry.endsWith(".jar") ||
                    entry.endsWith(".dex") ||
                    entry.endsWith(".zip")
            if (!looksLikeDexContainer) {
                return@forEachIndexed
            }

            if (firstOwnIndex >= 0 && index < firstOwnIndex) {
                prependSignals += VirtualizationSignal(
                    id = "virt_dex_prepend_${entry.stableId()}",
                    label = "Prepended third-party dex",
                    value = File(entry).name.ifBlank { "Third-party entry" },
                    group = VirtualizationSignalGroup.RUNTIME,
                    severity = VirtualizationSignalSeverity.DANGER,
                    detail = entry,
                    detailMonospace = true,
                )
            } else {
                otherUnexpectedEntries += entry
            }
        }

        val missingOwnPaths = ownPaths.filterNot { it in normalizedEntries }
        val mismatchDetail = buildString {
            if (missingOwnPaths.isNotEmpty()) {
                append("Missing from classloader:\n")
                append(missingOwnPaths.joinToString(separator = "\n"))
            }
            if (otherUnexpectedEntries.isNotEmpty()) {
                if (isNotEmpty()) append("\n\n")
                append("Unexpected classpath entries:\n")
                append(otherUnexpectedEntries.joinToString(separator = "\n"))
            }
        }
        val normalizedSourceDir = normalizePath(sourceDir)
        val ownSourceMissing =
            normalizedSourceDir.isNotBlank() && normalizedSourceDir !in normalizedEntries
        val mismatchSeverity = when {
            ownSourceMissing -> VirtualizationSignalSeverity.DANGER
            hostSignals.isNotEmpty() -> VirtualizationSignalSeverity.DANGER
            else -> VirtualizationSignalSeverity.WARNING
        }
        val mismatchSignal = if (mismatchDetail.isNotBlank()) {
            listOf(
                VirtualizationSignal(
                    id = "virt_dex_mismatch",
                    label = "Classpath/source mismatch",
                    value = "Review",
                    group = VirtualizationSignalGroup.CONSISTENCY,
                    severity = mismatchSeverity,
                    detail = mismatchDetail,
                    detailMonospace = true,
                ),
            )
        } else {
            emptyList()
        }

        val signals = (hostSignals + prependSignals + mismatchSignal)
            .distinctBy { it.id }

        return DexPathProbeResult(
            classPathEntries = normalizedEntries,
            entryCount = normalizedEntries.size,
            hitCount = signals.count {
                it.severity == VirtualizationSignalSeverity.DANGER ||
                        it.severity == VirtualizationSignalSeverity.WARNING
            },
            signals = signals,
            sourceDir = normalizedSourceDir,
            splitSourceDirs = splitSourceDirs.map(::normalizePath).filter { it.isNotBlank() },
            hostPathHit = hostSignals.isNotEmpty(),
        )
    }

    protected open fun collectClassPathEntries(classLoader: ClassLoader?): List<String> {
        val loader = classLoader ?: return emptyList()
        val reflectedEntries = collectFromDexElements(loader)
        if (reflectedEntries.isNotEmpty()) {
            return reflectedEntries
        }
        return parseClassLoaderDescription(loader.toString())
    }

    private fun collectFromDexElements(classLoader: ClassLoader): List<String> {
        if (classLoader !is BaseDexClassLoader) {
            return emptyList()
        }
        return runCatching {
            val pathListField = findField(classLoader.javaClass, "pathList")
            val pathList = pathListField.get(classLoader) ?: return emptyList()
            val dexElementsField = findField(pathList.javaClass, "dexElements")
            val dexElements = dexElementsField.get(pathList) as? Array<*> ?: return emptyList()
            dexElements.mapNotNull { element ->
                when {
                    element == null -> null
                    else -> collectDexElementPath(element)
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun collectDexElementPath(element: Any): String? {
        val dexFilePath = runCatching {
            val dexFileField = findField(element.javaClass, "dexFile")
            val dexFile = dexFileField.get(element)
            val method = dexFile?.javaClass?.methods?.firstOrNull { it.name == "getName" }
            method?.invoke(dexFile) as? String
        }.getOrNull()
        if (!dexFilePath.isNullOrBlank()) {
            return dexFilePath
        }

        val pathFields = listOf("path", "file", "zip")
        pathFields.forEach { fieldName ->
            val candidate = runCatching {
                val field = findField(element.javaClass, fieldName)
                field.get(element)
            }.getOrNull()
            when (candidate) {
                is File -> return candidate.absolutePath
                is String -> if (candidate.isNotBlank()) return candidate
            }
        }
        return null
    }

    private fun parseClassLoaderDescription(description: String): List<String> {
        val bracketContent = description.substringAfter('[', "")
            .substringBeforeLast(']', "")
            .ifBlank { description }
        return bracketContent
            .split(':', ',', ';')
            .map { it.trim() }
            .filter { it.contains('/') && !it.endsWith(".oat") && !it.endsWith(".vdex") }
    }

    private fun findField(type: Class<*>, name: String): Field {
        var current: Class<*>? = type
        while (current != null) {
            runCatching {
                return current.getDeclaredField(name).apply { isAccessible = true }
            }
            current = current.superclass
        }
        error("Field $name not found on ${type.name}")
    }

    private fun isSystemPath(path: String): Boolean {
        return path.startsWith("/system/") ||
                path.startsWith("/apex/") ||
                path.startsWith("/product/") ||
                path.startsWith("/vendor/") ||
                path.startsWith("/system_ext/") ||
                path.endsWith(".oat") ||
                path.endsWith(".vdex") ||
                path.endsWith(".art")
    }

    private fun isOwnOverlayPath(path: String, packageName: String): Boolean {
        if (packageName.isBlank()) {
            return false
        }
        val overlayMarker = "/$packageName/code_cache/.overlay/"
        return path.contains(overlayMarker) &&
                (path.endsWith(".dex") || path.endsWith(".jar") || path.endsWith(".zip") || path.endsWith(
                    ".apk"
                ))
    }

    private fun normalizePath(path: String): String {
        return path.trim()
            .replace('\\', '/')
            .substringBefore("!/")
            .ifBlank { "" }
    }

    private fun String.stableId(): String = hashCode().toUInt().toString(16)
}
