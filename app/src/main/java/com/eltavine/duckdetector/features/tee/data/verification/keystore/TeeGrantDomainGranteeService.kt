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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process

class TeeGrantDomainGranteeService : Service() {

    private val binder = object : Binder() {
        override fun onTransact(
            code: Int,
            data: Parcel,
            reply: Parcel?,
            flags: Int,
        ): Boolean {
            return when (code) {
                INTERFACE_TRANSACTION -> {
                    reply?.writeString(TeeGrantDomainGranteeProtocol.DESCRIPTOR)
                    true
                }

                TeeGrantDomainGranteeProtocol.TRANSACTION_GET_UID -> {
                    data.enforceInterface(TeeGrantDomainGranteeProtocol.DESCRIPTOR)
                    reply?.writeNoException()
                    reply?.writeInt(Process.myUid())
                    true
                }

                TeeGrantDomainGranteeProtocol.TRANSACTION_READ_GRANTED_CHAIN -> {
                    data.enforceInterface(TeeGrantDomainGranteeProtocol.DESCRIPTOR)
                    val grantId = data.readLong()
                    val keystore2Binder = data.readStrongBinder()
                    val result = readGrantedCertificateChain(grantId, keystore2Binder)
                    reply?.writeNoException()
                    result.writeToParcel(reply)
                    true
                }

                else -> super.onTransact(code, data, reply, flags)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun readGrantedCertificateChain(
        grantId: Long,
        keystore2Binder: IBinder?,
    ): TeeGrantDomainGranteeChainResult {
        if (keystore2Binder == null) {
            return TeeGrantDomainGranteeChainResult(
                available = false,
                detail = "isolated binder call blocked: owner did not pass keystore2 binder.",
            )
        }
        return runCatching {
            val result = Keystore2PrivateGrantClient().readGrantChain(keystore2Binder, grantId)
            TeeGrantDomainGranteeChainResult(
                available = result.available,
                chain = result.chain,
                detail = result.detail.ifBlank { "isolated private binder readback blocked." },
            )
        }.getOrElse { throwable ->
            TeeGrantDomainGranteeChainResult(
                available = false,
                detail = "isolated binder call blocked: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
            )
        }
    }
}

object TeeGrantDomainGranteeProtocol {
    const val DESCRIPTOR = "com.eltavine.duckdetector.features.tee.data.verification.keystore.ITeeGrantDomainGrantee"
    const val TRANSACTION_GET_UID = IBinder.FIRST_CALL_TRANSACTION
    const val TRANSACTION_READ_GRANTED_CHAIN = IBinder.FIRST_CALL_TRANSACTION + 1
}

data class TeeGrantDomainGranteeChainResult(
    val available: Boolean = false,
    val chain: GrantDomainCertificateChain = GrantDomainCertificateChain(),
    val detail: String = "",
) {
    fun writeToParcel(reply: Parcel?) {
        reply ?: return
        reply.writeInt(if (available) 1 else 0)
        reply.writeInt(chain.certificates.size)
        chain.certificates.forEach { certificate ->
            reply.writeInt(certificate.derLength)
            reply.writeString(certificate.sha256)
        }
        reply.writeString(detail)
    }

    companion object {
        fun readFromParcel(reply: Parcel): TeeGrantDomainGranteeChainResult {
            val available = reply.readInt() != 0
            val size = reply.readInt().coerceAtLeast(0)
            val certificates = buildList {
                repeat(size) {
                    add(
                        GrantDomainCertificateFingerprint(
                            derLength = reply.readInt(),
                            sha256 = reply.readString().orEmpty(),
                        ),
                    )
                }
            }
            return TeeGrantDomainGranteeChainResult(
                available = available,
                chain = GrantDomainCertificateChain(certificates),
                detail = reply.readString().orEmpty(),
            )
        }
    }
}
