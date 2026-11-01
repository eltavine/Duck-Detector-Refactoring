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

package com.eltavine.duckdetector.features.networkrisk.data.network

/** Bounded adjacent reads; does not claim an atomic snapshot or exclude an ABA transition. */
internal class RepeatedNetworkSampler<T>(private val read: () -> T) {
    data class Result<T>(val value: T, val repeated: Boolean, val attempts: Int)

    fun collect(): Result<T> {
        repeat(2) { attempt ->
            val before = read()
            val after = read()
            if (before == after) return Result(after, true, attempt + 1)
            if (attempt == 1) return Result(after, false, 2)
        }
        error("Unreachable")
    }
}
