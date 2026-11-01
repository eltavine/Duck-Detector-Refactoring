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

package com.eltavine.duckdetector.features.nativeroot.data.probes

internal object KernelSuTimingCpuList {
    fun parse(raw: String): List<Int> {
        require(raw.length <= 8192)
        val text = raw.trim()
        if (text.isEmpty()) return emptyList()
        val cpus = text.split(',').flatMap { token ->
            require(token.matches(Regex("[0-9]+(-[0-9]+)?")))
            val range = token.split('-').map { it.toInt().also { cpu -> require(cpu in 0..1023) } }
            val first = range.first()
            val last = range.last()
            require(first <= last)
            (first..last).toList()
        }
        require(cpus.size <= 1024 && cpus == cpus.distinct().sorted())
        return cpus
    }
}
