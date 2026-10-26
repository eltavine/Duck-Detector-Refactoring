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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import com.eltavine.duckdetector.core.evidence.ScanEpoch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Gives every detector that reads the carrier during one scan the same collection.
 *
 * Concurrent SELinux and LSPosed detectors share the identity of the dashboard/SDK scan that
 * spawned them. Wall-clock ordering alone cannot distinguish late requests in the same scan from
 * a subsequent scan, so only the exact epoch ID reuses a result.
 */
internal class ScanSharedCollection<T : Any> {
    private val mutex = Mutex()
    private var latest: Collected<T>? = null

    suspend fun collect(scan: ScanEpoch, collect: suspend () -> T): T = mutex.withLock {
        latest?.takeIf { it.scanId == scan.id }?.let { return@withLock it.value }
        val value = collect()
        latest = Collected(scan.id, value)
        value
    }

    private class Collected<T>(val scanId: Long, val value: T)
}
