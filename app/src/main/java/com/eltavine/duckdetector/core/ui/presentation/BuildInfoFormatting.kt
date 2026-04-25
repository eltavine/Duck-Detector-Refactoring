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

package com.eltavine.duckdetector.core.ui.presentation

fun formatBuildTimeUtc(raw: String): String {
    if (raw.length != 14 || raw.any { !it.isDigit() }) {
        return raw
    }
    return buildString {
        append(raw.substring(0, 4))
        append('-')
        append(raw.substring(4, 6))
        append('-')
        append(raw.substring(6, 8))
        append(' ')
        append(raw.substring(8, 10))
        append(':')
        append(raw.substring(10, 12))
        append(':')
        append(raw.substring(12, 14))
    }
}
