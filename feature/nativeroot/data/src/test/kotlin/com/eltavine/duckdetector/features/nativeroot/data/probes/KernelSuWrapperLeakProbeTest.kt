package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuWrapperLeakObservation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import com.eltavine.duckdetector.features.nativeroot.domain.WrapperLeakCollection
import org.junit.Assert.assertSame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class KernelSuWrapperLeakProbeTest {
    @Test fun `repeated and concurrent callers reuse one bounded experiment`() = runBlocking {
        var calls = 0
        val expected = KernelSuWrapperLeakObservation()
        val probe = KernelSuWrapperLeakProbe { calls++; expected }
        val results = List(8) { async(Dispatchers.Default) { probe.collect() } }
        results.forEach { assertEquals(expected, it.await()) }
        assertEquals(expected, probe.collect())
        assertEquals(1, calls)
    }
    @Test fun `cancellation after a stimulus cannot authorize another experiment`() = runBlocking {
        var calls = 0
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val expected = KernelSuWrapperLeakObservation()
        val probe = KernelSuWrapperLeakProbe {
            calls++
            entered.countDown()
            check(release.await(2, TimeUnit.SECONDS))
            expected
        }
        val task = async(Dispatchers.Default) { probe.collect() }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        task.cancel()
        release.countDown()
        task.join()
        assertEquals(expected, probe.collect())
        assertEquals(1, calls)
    }
    @Test fun `exceptions after entering collection retain consumed admission`() = runBlocking {
        for (failure in listOf(IllegalStateException("injected failure"), CancellationException("injected cancellation"))) {
            var calls = 0
            val probe = KernelSuWrapperLeakProbe { calls++; throw failure }
            val thrown = runCatching { probe.collect() }.exceptionOrNull()
            assertSame(failure, thrown)
            assertEquals(WrapperLeakCollection.UNAVAILABLE, probe.collect().collection)
            assertEquals(1, calls)
        }
    }
    @Test fun `cancellation before admission does not consume the experiment`() = runBlocking {
        var calls = 0
        val expected = KernelSuWrapperLeakObservation()
        val probe = KernelSuWrapperLeakProbe { calls++; expected }
        val task = async(Dispatchers.Default, start = CoroutineStart.LAZY) { probe.collect() }
        task.cancel()
        task.join()
        assertEquals(0, calls)
        assertEquals(expected, probe.collect())
        assertEquals(1, calls)
    }
}
