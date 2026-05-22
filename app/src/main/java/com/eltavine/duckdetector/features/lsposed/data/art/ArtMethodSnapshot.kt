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

package com.eltavine.duckdetector.features.lsposed.data.art

data class ArtMethodSnapshot(
    val available: Boolean = false,
    val methodCount: Int = 0,
    val candidateCount: Int = 0,
    val suspiciousCandidateCount: Int = 0,
    val methods: List<ArtMethodEntry> = emptyList(),
) {
    val primaryCandidates: List<ArtMethodCandidate>
        get() = methods.mapNotNull { it.primaryCandidate }
}

data class ArtMethodEntry(
    val label: String,
    val artMethodAddress: String,
    val declaredCandidateCount: Int,
    val candidates: List<ArtMethodCandidate>,
) {
    val primaryCandidate: ArtMethodCandidate?
        get() = candidates.maxByOrNull { it.offset }
}

data class ArtMethodCandidate(
    val label: String,
    val offset: Int,
    val address: String,
    val regionKind: String,
    val mapStart: String,
    val mapOffset: String,
    val permissions: String,
    val suspicious: Boolean,
    val path: String,
    val detail: String,
) {
    val normalizedSignature: String
        get() = listOf(regionKind, pathFingerprint(path), mapOffset).joinToString("|")

    private fun pathFingerprint(value: String): String {
        val lower = value.lowercase()
        return when {
            lower.contains("/apex/com.android.art/") -> "/apex/com.android.art"
            lower.contains("/apex/com.android.runtime/") -> "/apex/com.android.runtime"
            lower.contains("boot.oat") -> "boot.oat"
            lower.contains("boot.art") -> "boot.art"
            lower.contains("/oat/") -> "/oat/"
            lower.contains("jit") || lower.contains("dalvik") -> "jit"
            lower.contains("(deleted)") -> "(deleted)"
            lower.contains("memfd:") -> "memfd"
            lower.isBlank() -> "<anonymous>"
            else -> value
        }
    }
}
