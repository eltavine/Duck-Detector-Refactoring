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

package com.eltavine.duckdetector.core.evidence

import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.coroutineContext

/** Immutable scan identity: Android callers provide elapsedRealtimeNanos, never wall time. */
public class ScanEpoch private constructor(
    public val id: Long,
    public val startedNanos: Long,
) : AbstractCoroutineContextElement(Key) {
    public val startedMillis: Long get() = startedNanos / 1_000_000L

    public companion object Key : CoroutineContext.Key<ScanEpoch> {
        private val nextId = AtomicLong()

        public fun begin(startedNanos: Long): ScanEpoch = ScanEpoch(nextId.incrementAndGet(), startedNanos)

        /** An ungrouped detector scan gets its own epoch; batch callers install one in the context. */
        public suspend fun current(clockNanos: () -> Long): ScanEpoch =
            coroutineContext[Key] ?: begin(clockNanos())
    }
}
