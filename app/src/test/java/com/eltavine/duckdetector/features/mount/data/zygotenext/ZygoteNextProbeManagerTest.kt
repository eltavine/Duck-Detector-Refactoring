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

package com.eltavine.duckdetector.features.mount.data.zygotenext

import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy

class ZygoteNextProbeManagerTest {

    @Test
    fun `bind failure is unavailable and does not unbind`() = runBlocking {
        val binding = FakeBinding { _ -> false }

        val result = manager(binding = binding).collect()

        assertEquals(ZygoteNextProbeState.UNAVAILABLE, result.state)
        assertTrue(result.errorDetail.contains("could not be bound"))
        assertEquals(0, binding.unbindCount)
    }

    @Test
    fun `null service binder is unavailable`() = runBlocking {
        val binding = FakeBinding { connection ->
            connection.onServiceConnected(null, null)
            true
        }

        val result = manager(binding = binding).collect()

        assertEquals(ZygoteNextProbeState.UNAVAILABLE, result.state)
        assertTrue(result.errorDetail.contains("null Binder"))
        assertEquals(1, binding.unbindCount)
    }

    @Test
    fun `null binding callback is unavailable`() = runBlocking {
        val binding = FakeBinding { connection ->
            connection.onNullBinding(null)
            true
        }

        val result = manager(binding = binding).collect()

        assertEquals(ZygoteNextProbeState.UNAVAILABLE, result.state)
        assertTrue(result.errorDetail.contains("null binding"))
        assertEquals(1, binding.unbindCount)
    }

    @Test
    fun `empty binder payload is unavailable`() = runBlocking {
        val binding = FakeBinding { connection ->
            connection.onServiceConnected(null, dummyBinder())
            true
        }

        val result = manager(
            binding = binding,
            payloadCollector = { "" },
        ).collect()

        assertEquals(ZygoteNextProbeState.UNAVAILABLE, result.state)
        assertTrue(result.errorDetail.contains("payload version"))
        assertEquals(1, binding.unbindCount)
    }

    @Test
    fun `timeout is unavailable and cancels binding`() = runBlocking {
        val binding = FakeBinding { _ -> true }

        val result = manager(
            binding = binding,
            timeoutMillis = 25L,
        ).collect()

        assertEquals(ZygoteNextProbeState.UNAVAILABLE, result.state)
        assertTrue(result.errorDetail.contains("timed out"))
        assertEquals(1, binding.unbindCount)
        assertEquals("master:1", result.mainProcess.rootPropagation)
    }

    private fun manager(
        binding: ZygoteNextServiceBinding,
        timeoutMillis: Long = 1_000L,
        payloadCollector: (IBinder) -> String = { error("Payload should not be queried.") },
    ): ZygoteNextProbeManager {
        return ZygoteNextProbeManager(
            sdkIntProvider = { 37 },
            localProbe = object : ZygoteNextLocalProbe() {
                override fun collect(): ZygoteNextProcessSnapshot {
                    return ZygoteNextProcessSnapshot(
                        available = true,
                        mountNamespaceInode = 10,
                        rootPropagation = "master:1",
                        mountCount = 100,
                    )
                }
            },
            serviceBinding = binding,
            timeoutMillis = timeoutMillis,
            payloadCollector = payloadCollector,
            testOnly = Unit,
        )
    }

    private fun dummyBinder(): IBinder {
        return Proxy.newProxyInstance(
            javaClass.classLoader,
            arrayOf(IBinder::class.java),
        ) { _, _, _ -> error("Dummy Binder methods must not be called.") } as IBinder
    }

    private class FakeBinding(
        private val bindAction: (ServiceConnection) -> Boolean,
    ) : ZygoteNextServiceBinding {
        var unbindCount: Int = 0
            private set

        override fun bind(connection: ServiceConnection): Boolean = bindAction(connection)

        override fun unbind(connection: ServiceConnection) {
            unbindCount += 1
        }
    }
}
