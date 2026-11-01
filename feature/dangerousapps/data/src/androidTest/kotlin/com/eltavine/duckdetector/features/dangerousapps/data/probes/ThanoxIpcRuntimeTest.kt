// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.data.probes

import android.os.Binder
import android.os.Parcel
import android.os.RemoteException
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.coroutines.cancellation.CancellationException

@RunWith(AndroidJUnit4::class)
class ThanoxIpcRuntimeTest {
    @Test fun validHandshakeReturnsMatchingServer() {
        val server = Binder().apply { attachInterface(null, DESCRIPTOR) }
        val result = ThanoxIpcProbe {
            bridge { reply -> reply.writeStrongBinder(server); true }
        }.run()
        assertEquals(ThanoxIpcState.MATCHED, result.state)
        assertEquals(DESCRIPTOR, result.observedDescriptor)
    }

    @Test fun nonemptyRemoteExceptionReplyIsNotThanox() {
        val result = ThanoxIpcProbe {
            bridge { reply -> reply.writeException(SecurityException("OEM interface rejection")); true }
        }.run()
        assertEquals(ThanoxIpcState.INCONCLUSIVE, result.state)
    }

    @Test fun nonemptySuccessHeaderWithoutBinderIsNotThanox() {
        val result = ThanoxIpcProbe {
            bridge { reply -> reply.writeNoException(); true }
        }.run()
        assertEquals(ThanoxIpcState.INCONCLUSIVE, result.state)
    }

    @Test fun unrelatedReturnedBinderIsNotThanoxEvenWhenOuterDescriptorMatches() {
        val unrelated = Binder().apply { attachInterface(null, "android.example.IOemService") }
        val outer = bridge { reply -> reply.writeStrongBinder(unrelated); true }
            .apply { attachInterface(null, DESCRIPTOR) }
        val result = ThanoxIpcProbe { outer }.run()
        assertEquals(ThanoxIpcState.INCONCLUSIVE, result.state)
        assertEquals("android.example.IOemService", result.observedDescriptor)
    }

    @Test fun serverWithoutDescriptorIsInconclusive() {
        val result = ThanoxIpcProbe {
            bridge { reply -> reply.writeStrongBinder(Binder()); true }
        }.run()
        assertEquals(ThanoxIpcState.INCONCLUSIVE, result.state)
    }

    @Test fun emptyReplyIsInconclusive() {
        assertEquals(ThanoxIpcState.INCONCLUSIVE, ThanoxIpcProbe { bridge { true } }.run().state)
    }

    @Test fun nullServerIsInconclusive() {
        assertEquals(ThanoxIpcState.INCONCLUSIVE, ThanoxIpcProbe {
            bridge { reply -> reply.writeStrongBinder(null); true }
        }.run().state)
    }

    @Test fun unhandledTransactionDoesNotParseUnrelatedReplyBytes() {
        assertEquals(ThanoxIpcState.NOT_OBSERVED, ThanoxIpcProbe {
            bridge { reply -> reply.writeException(SecurityException("Ignored reply")); false }
        }.run().state)
    }

    @Test fun unavailableServiceIsNotClean() {
        assertEquals(ThanoxIpcState.UNAVAILABLE, ThanoxIpcProbe { null }.run().state)
    }

    @Test fun lookupDenialIsNotClean() {
        assertEquals(ThanoxIpcState.UNAVAILABLE, ThanoxIpcProbe { throw SecurityException() }.run().state)
    }

    @Test fun transportFailureIsNotClean() {
        assertEquals(ThanoxIpcState.UNAVAILABLE, ThanoxIpcProbe {
            bridge { throw RemoteException("Binder died") }
        }.run().state)
    }

    @Test fun descriptorTransportFailureIsNotClean() {
        val unavailable = object : Binder() {
            override fun getInterfaceDescriptor(): String = throw RemoteException("Binder died")
        }
        assertEquals(ThanoxIpcState.UNAVAILABLE, ThanoxIpcProbe {
            bridge { reply -> reply.writeStrongBinder(unavailable); true }
        }.run().state)
    }

    @Test(expected = CancellationException::class)
    fun cancellationPropagates() {
        ThanoxIpcProbe { bridge { throw CancellationException("Cancelled") } }.run()
    }

    @Test fun frameworkDropBoxDoesNotIdentifyThanoxOnStockEmulator() {
        val result = ThanoxIpcProbe().run()
        Log.i("ThanoxIpcTest", "framework state=${result.state} descriptor=${result.observedDescriptor}")
        assertNotEquals(ThanoxIpcState.MATCHED, result.state)
    }

    private fun bridge(response: (Parcel) -> Boolean) = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            assertEquals("github.tornaco.android.thanos.core.IPC_TRANS_CODE_THANOS_SERVER".hashCode(), code)
            assertEquals(0, flags)
            data.enforceInterface(DESCRIPTOR)
            return response(requireNotNull(reply))
        }
    }
}

private const val DESCRIPTOR = "github.tornaco.android.thanos.core.IThanos"
