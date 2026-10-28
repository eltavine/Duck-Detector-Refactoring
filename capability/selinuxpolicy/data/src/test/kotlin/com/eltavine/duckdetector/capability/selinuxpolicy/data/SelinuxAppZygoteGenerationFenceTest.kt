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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAppZygoteGenerationFenceTest {
    private val key = SelinuxAppZygoteGenerationKey(
        preloadPid = 1234,
        appUid = 10234,
        startedNanos = 99_000_000L,
        apkPath = "/data/app/current/base.apk",
        splitPaths = listOf("/data/app/current/split_config.arm64_v8a.apk"),
        versionCode = 321L,
        payloadSchemaVersion = 1,
        buildRevision = "abc123def456",
    )

    @Test
    fun `same preload generation has a stable persisted identity`() {
        assertEquals(key.storageKey(), key.copy().storageKey())
        assertEquals(64, key.storageKey().length)
    }

    @Test
    fun `every provenance dimension participates in the generation identity`() {
        val variants = listOf(
            key.copy(preloadPid = key.preloadPid + 1),
            key.copy(appUid = key.appUid + 1),
            key.copy(startedNanos = key.startedNanos + 1),
            key.copy(apkPath = "/data/app/other/base.apk"),
            key.copy(splitPaths = emptyList()),
            key.copy(versionCode = key.versionCode + 1),
            key.copy(payloadSchemaVersion = key.payloadSchemaVersion + 1),
            key.copy(buildRevision = "different-build"),
        )
        variants.forEach { assertNotEquals(key.storageKey(), it.storageKey()) }
    }

    @Test
    fun `accepted generation remains rejected by a new store instance`() {
        val backing = mutableSetOf<String>()
        val firstProcessStore = MemoryStore(backing)
        assertEquals(GenerationFenceCheck.NOT_ACCEPTED, firstProcessStore.check(key))
        assertTrue(firstProcessStore.commitAccepted(key))

        // A fresh store instance models a main-process restart while retaining persistent storage.
        val restartedProcessStore = MemoryStore(backing)
        assertEquals(GenerationFenceCheck.ALREADY_ACCEPTED, restartedProcessStore.check(key))
        assertEquals(GenerationFenceCheck.NOT_ACCEPTED, restartedProcessStore.check(key.copy(preloadPid = 5678)))
    }

    private class MemoryStore(
        private val persistedKeys: MutableSet<String>,
    ) : SelinuxAppZygoteGenerationStore {
        override fun check(key: SelinuxAppZygoteGenerationKey): GenerationFenceCheck =
            if (key.storageKey() in persistedKeys) GenerationFenceCheck.ALREADY_ACCEPTED
            else GenerationFenceCheck.NOT_ACCEPTED

        override fun commitAccepted(key: SelinuxAppZygoteGenerationKey): Boolean =
            persistedKeys.add(key.storageKey())
    }
}
