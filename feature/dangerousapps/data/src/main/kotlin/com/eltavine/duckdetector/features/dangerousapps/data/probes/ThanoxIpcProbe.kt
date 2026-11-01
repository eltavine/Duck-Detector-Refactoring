// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.dangerousapps.data.probes

import android.os.IBinder
import android.os.Parcel
import android.os.RemoteException
import com.eltavine.duckdetector.core.platform.HiddenServiceManager
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcReport
import com.eltavine.duckdetector.features.dangerousapps.domain.ThanoxIpcState
import kotlin.coroutines.cancellation.CancellationException

class ThanoxIpcProbe(
    private val serviceLookup: () -> IBinder? = {
        HiddenServiceManager.getService("dropbox").getOrThrow()
    },
) {
    fun run(): ThanoxIpcReport {
        val service = try {
            serviceLookup() ?: return ThanoxIpcReport(
                ThanoxIpcState.UNAVAILABLE, detail = "The system dropbox service was unavailable.",
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            return ThanoxIpcReport(
                ThanoxIpcState.UNAVAILABLE, detail = "The system dropbox service could not be queried.",
            )
        }

        val data = Parcel.obtain()
        try {
            val reply = Parcel.obtain()
            try {
                // Thanox d964e893: DropBoxManagerProxyProvider enforces IThanos,
                // then writes a raw strong Binder, without an AIDL exception header.
                data.writeInterfaceToken(THANOX_DESCRIPTOR)
                if (!service.transact(THANOX_TRANSACTION, data, reply, 0)) {
                    return ThanoxIpcReport(
                        ThanoxIpcState.NOT_OBSERVED, detail = "The Thanox transaction was not handled.",
                    )
                }
                if (reply.dataSize() == 0) {
                    return ThanoxIpcReport(
                        ThanoxIpcState.INCONCLUSIVE, detail = "The transaction returned an empty reply.",
                    )
                }
                reply.setDataPosition(0)
                val server = reply.readStrongBinder() ?: return ThanoxIpcReport(
                    ThanoxIpcState.INCONCLUSIVE, detail = "The reply contained no server Binder.",
                )
                // An exception Parcel can accompany transact=true. A nonempty reply
                // or a live unrelated Binder does not establish the server's identity.
                val descriptor = server.interfaceDescriptor
                return if (descriptor == THANOX_DESCRIPTOR) {
                    ThanoxIpcReport(ThanoxIpcState.MATCHED, observedDescriptor = descriptor)
                } else {
                    ThanoxIpcReport(
                        ThanoxIpcState.INCONCLUSIVE, observedDescriptor = descriptor,
                        detail = "The returned Binder did not expose the Thanox interface.",
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: SecurityException) {
                return ThanoxIpcReport(
                    ThanoxIpcState.UNAVAILABLE, detail = "The IPC query was denied.",
                )
            } catch (_: RemoteException) {
                return ThanoxIpcReport(
                    ThanoxIpcState.UNAVAILABLE, detail = "The IPC transport or returned Binder was unavailable.",
                )
            } catch (_: RuntimeException) {
                return ThanoxIpcReport(
                    ThanoxIpcState.INCONCLUSIVE, detail = "The IPC reply was malformed or unrecognized.",
                )
            } finally {
                reply.recycle()
            }
        } finally {
            data.recycle()
        }
    }
}

private const val THANOX_DESCRIPTOR = "github.tornaco.android.thanos.core.IThanos"
private val THANOX_TRANSACTION =
    "github.tornaco.android.thanos.core.IPC_TRANS_CODE_THANOS_SERVER".hashCode()
