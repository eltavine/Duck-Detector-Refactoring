/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.heapresidue.data.hprof

import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueArgument
import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueSignal

/**
 * Anchored fixed-prefix dispatch followed by exact hash lookup, never a risk-name substring search.
 *
 * Arguments naming [host] are neither candidates nor matches: every fresh child carries its own
 * startup arguments, so they show nothing about whether residue of other launches is visible.
 */
internal class StartupArgumentMatcher(private val targets: Set<String>, private val host: String? = null) {
    private val matches = linkedMapOf<String, MutableSet<HeapResidueArgument>>()
    var candidates = 0
        private set

    fun accept(value: String) {
        val argument: HeapResidueArgument
        val packageName: String
        when {
            value.startsWith("--package-name=") -> {
                argument = HeapResidueArgument.PACKAGE_NAME
                packageName = value.substring(15)
            }
            value.startsWith("--nice-name=") -> {
                argument = HeapResidueArgument.NICE_NAME
                val suffix = value.substring(12)
                val colon = suffix.indexOf(':')
                if (colon >= 0 && (colon == suffix.lastIndex || !suffix.substring(colon + 1).all(::processChar))) return
                packageName = suffix.substringBefore(':')
            }
            value.startsWith("--app-data-dir=") -> {
                argument = HeapResidueArgument.APP_DATA_DIR
                packageName = dataPackage(value.substring(15)) ?: return
            }
            else -> return
        }
        if (!validPackage(packageName) || packageName == host) return
        if (candidates == Int.MAX_VALUE) throw HprofFormatException("Too many candidate strings")
        candidates++
        if (packageName in targets) matches.getOrPut(packageName) { linkedSetOf() }.add(argument)
    }

    fun result(): List<HeapResidueSignal> = matches.map { (name, arguments) ->
        HeapResidueSignal(name, HeapResidueArgument.entries.filter { it in arguments }.toSet())
    }.sortedBy { it.packageName }

    // These are serialized arguments being parsed, not filesystem paths opened by the host.
    @Suppress("SdCardPath")
    private fun dataPackage(path: String): String? {
        if (path.startsWith("/data/data/")) return path.substring(11).takeIf { '/' !in it }
        val prefix = when {
            path.startsWith("/data/user/") -> "/data/user/"
            path.startsWith("/data/user_de/") -> "/data/user_de/"
            else -> return null
        }
        val tail = path.substring(prefix.length)
        val slash = tail.indexOf('/')
        if (slash <= 0 || !tail.substring(0, slash).all { it in '0'..'9' }) return null
        if (tail.substring(0, slash).toIntOrNull() == null) return null
        return tail.substring(slash + 1).takeIf { '/' !in it }
    }

    private fun validPackage(value: String): Boolean {
        if (value.length > 255 || '.' !in value) return false
        var start = true
        for (c in value) {
            if (c == '.') {
                if (start) return false
                start = true
            } else {
                if (start && !letter(c)) return false
                if (!letter(c) && c !in '0'..'9' && c != '_') return false
                start = false
            }
        }
        return !start
    }

    private fun letter(c: Char): Boolean = c in 'a'..'z' || c in 'A'..'Z'
    private fun processChar(c: Char): Boolean = letter(c) || c in '0'..'9' || c == '_' || c == '.' || c == '-' || c == ':'
}
