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

package com.eltavine.duckdetector.features.playintegrityfix.data.utils

import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixGroup
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignal
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSignalSeverity
import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixSource

class PlayIntegrityConsistencyUtils {

    fun buildSourceMismatchSignals(
        reads: Collection<PlayIntegrityMultiSourceRead>,
    ): List<PlayIntegrityFixSignal> {
        return reads.mapNotNull { read ->
            val nonBlankValues = read.sourceValues.filterValues { it.isNotBlank() }
            if (nonBlankValues.size < 2) {
                return@mapNotNull null
            }
            val distinctValues = nonBlankValues.values.map { it.trim() }.distinct()
            if (distinctValues.size < 2) {
                return@mapNotNull null
            }

            PlayIntegrityFixSignal(
                id = "mismatch_${read.rule.property}",
                label = "${read.rule.label} source mismatch",
                value = "Mismatch",
                group = PlayIntegrityFixGroup.CONSISTENCY,
                category = read.rule.category,
                severity = PlayIntegrityFixSignalSeverity.WARNING,
                source = PlayIntegrityFixSource.NATIVE_LIBC,
                detail = buildString {
                    append(read.rule.property)
                    append('\n')
                    nonBlankValues.forEach { (source, value) ->
                        append(source.label)
                        append(": ")
                        append(value)
                        append('\n')
                    }
                }.trim(),
                detailMonospace = true,
            )
        }
    }
}
