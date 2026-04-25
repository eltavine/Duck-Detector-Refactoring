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

data class LSPosedClassLoaderProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedClassLoaderProbe {

    fun run(): LSPosedClassLoaderProbeResult {
        return evaluate(
            startingLoaders = listOf(
                javaClass.classLoader,
                Thread.currentThread().contextClassLoader,
            ),
        )
    }

    internal fun evaluate(
        startingLoaders: List<ClassLoader?>,
        maxDepth: Int = MAX_CHAIN_DEPTH,
    ): LSPosedClassLoaderProbeResult {
        val signals = mutableListOf<LSPosedSignal>()
        val visitedLoaders = linkedSetOf<ClassLoader>()
        val suspiciousLoaders = linkedMapOf<String, List<String>>()
        val longestChain = mutableListOf<String>()

        startingLoaders.forEach { startingLoader ->
            var current = startingLoader
            var depth = 0
            val chain = mutableListOf<String>()

            while (current != null && depth < maxDepth) {
                if (!visitedLoaders.add(current)) {
                    break
                }

                val loaderName = current.javaClass.name
                chain += loaderName
                if (containsFrameworkToken(loaderName)) {
                    suspiciousLoaders.putIfAbsent(loaderName, chain.toList())
                }

                current = current.parent
                depth++
            }

            if (chain.size > longestChain.size) {
                longestChain.clear()
                longestChain += chain
            }
        }

        suspiciousLoaders.forEach { (loaderName, chain) ->
            signals += LSPosedSignal(
                id = "classloader_${loaderName.toSignalIdSegment()}",
                label = "ClassLoader token",
                value = "Injected",
                group = LSPosedSignalGroup.RUNTIME,
                severity = LSPosedSignalSeverity.DANGER,
                detail = buildString {
                    appendLine("Suspicious loader: $loaderName")
                    if (chain.isNotEmpty()) {
                        appendLine("Chain:")
                        chain.forEach { name -> appendLine(name) }
                    }
                }.trim(),
                detailMonospace = true,
            )
        }

        if (signals.isEmpty() && longestChain.size > DEEP_CHAIN_THRESHOLD) {
            signals += LSPosedSignal(
                id = "classloader_deep_chain",
                label = "ClassLoader chain",
                value = "Deep",
                group = LSPosedSignalGroup.RUNTIME,
                severity = LSPosedSignalSeverity.WARNING,
                detail = buildString {
                    appendLine("Observed unusually deep ClassLoader chain (${longestChain.size} levels).")
                    longestChain.forEach { name -> appendLine(name) }
                }.trim(),
                detailMonospace = true,
            )
        }

        return LSPosedClassLoaderProbeResult(
            signals = signals,
            hitCount = signals.size,
        )
    }

    private companion object {
        private const val MAX_CHAIN_DEPTH = 10
        private const val DEEP_CHAIN_THRESHOLD = 5
    }
}
