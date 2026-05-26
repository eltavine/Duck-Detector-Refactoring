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

                TeeGrantDomainGranteeProtocol.TRANSACTION_READ_GRANTED_CHAIN_PUBLIC -> {
                    data.enforceInterface(TeeGrantDomainGranteeProtocol.DESCRIPTOR)
                    val grantId = data.readLong()
                    val result = readGrantedCertificateChainJavaApi(grantId, hiddenApi = false)
                    reply?.writeNoException()
                    result.writeToParcel(reply)
                    true
                }

                TeeGrantDomainGranteeProtocol.TRANSACTION_READ_GRANTED_CHAIN_HIDDEN -> {
                    data.enforceInterface(TeeGrantDomainGranteeProtocol.DESCRIPTOR)
                    val grantId = data.readLong()
                    val result = readGrantedCertificateChainJavaApi(grantId, hiddenApi = true)
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
        // The isolated service must not resolve Keystore2 on its own: owner-passed binder is the
        // explicit capability under test, and denial here is reported as blocked/unavailable.
        // isolated service 不自行解析 Keystore2：owner 传入的 binder 才是本检测验证的能力；这里被拒绝时按 blocked/unavailable 上报。
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
                errorKind = result.errorKind,
                chain = result.chain,
                detail = result.detail.ifBlank { "isolated private binder readback blocked." },
                diagnosticCopyText = result.throwable
                    ?.stackTraceToString()
                    ?.trim()
                    .orEmpty(),
            )
        }.getOrElse { throwable ->
            TeeGrantDomainGranteeChainResult(
                available = false,
                errorKind = classifyKeystore2PrivateGrantFailure(
                    throwableClassName = throwable.rootCauseClassName(),
                    message = throwable.rootCauseMessage(),
                    serviceSpecificErrorCode = throwable.serviceSpecificErrorCode(),
                ),
                detail = "isolated binder call blocked: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                diagnosticCopyText = throwable.stackTraceToString().trim(),
            )
        }
    }

    private fun readGrantedCertificateChainJavaApi(
        grantId: Long,
        hiddenApi: Boolean,
    ): TeeGrantDomainGranteeChainResult {
        // Public and hidden readback both stay on KeyStoreManager semantics; hidden only changes how
        // the isolated process reaches methods that may be hidden below Android 16.
        // public 与 hidden 回读都保持 KeyStoreManager 语义；hidden 只改变 isolated 进程访问 Android 16 以下隐藏方法的方式。
        val apiResult = if (hiddenApi) {
            KeyStoreGrantJavaApis.hiddenApi(this)
        } else {
            KeyStoreGrantJavaApis.publicApi(this)
        }
        apiResult.throwable?.let { throwable ->
            return TeeGrantDomainGranteeChainResult(
                available = false,
                detail = apiResult.detail,
                diagnosticCopyText = throwable.stackTraceToString().trim(),
            )
        }
        val api = apiResult.api ?: return TeeGrantDomainGranteeChainResult(
            available = false,
            detail = apiResult.detail,
        )
        val stage = api.stageLabel.lowercase()
        return runCatching {
            val chain = api.getGrantedCertificateChainFromId(grantId)
            TeeGrantDomainGranteeChainResult(
                available = true,
                chain = GrantDomainCertificateChain.fromCertificates(chain),
                detail = "$stage isolated readback chainLength=${chain.size}",
            )
        }.getOrElse { throwable ->
            TeeGrantDomainGranteeChainResult(
                available = false,
                errorKind = classifyKeystore2PrivateGrantFailure(
                    throwableClassName = throwable.rootCauseClassName(),
                    message = throwable.rootCauseMessage(),
                    serviceSpecificErrorCode = throwable.serviceSpecificErrorCode(),
                ),
                detail = "$stage isolated readback failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                diagnosticCopyText = throwable.stackTraceToString().trim(),
            )
        }
    }
}

private fun Throwable.rootCause(): Throwable {
    var current = this
    while (current.cause != null && current.cause !== current) {
        current = current.cause!!
    }
    return current
}

private fun Throwable.rootCauseClassName(): String = rootCause().javaClass.name

private fun Throwable.rootCauseMessage(): String? = rootCause().message

private fun Throwable.serviceSpecificErrorCode(): Int? {
    var current: Throwable? = this
    while (current != null) {
        if (current.javaClass.name == "android.os.ServiceSpecificException") {
            return runCatching {
                val field = current.javaClass.getField("errorCode")
                field.isAccessible = true
                field.get(current) as? Int
            }.getOrNull()
        }
        current = current.cause
    }
    return null
}

object TeeGrantDomainGranteeProtocol {
    const val DESCRIPTOR = "com.eltavine.duckdetector.features.tee.data.verification.keystore.ITeeGrantDomainGrantee"
    const val TRANSACTION_GET_UID = IBinder.FIRST_CALL_TRANSACTION
    const val TRANSACTION_READ_GRANTED_CHAIN = IBinder.FIRST_CALL_TRANSACTION + 1
    const val TRANSACTION_READ_GRANTED_CHAIN_PUBLIC = IBinder.FIRST_CALL_TRANSACTION + 2
    const val TRANSACTION_READ_GRANTED_CHAIN_HIDDEN = IBinder.FIRST_CALL_TRANSACTION + 3
}

data class TeeGrantDomainGranteeChainResult(
    val available: Boolean = false,
    val errorKind: Keystore2PrivateGrantErrorKind = Keystore2PrivateGrantErrorKind.NONE,
    val chain: GrantDomainCertificateChain = GrantDomainCertificateChain(),
    val detail: String = "",
    val diagnosticCopyText: String = "",
) {
    fun writeToParcel(reply: Parcel?) {
        reply ?: return
        reply.writeInt(if (available) 1 else 0)
        reply.writeString(errorKind.name)
        reply.writeInt(chain.certificates.size)
        chain.certificates.forEach { certificate ->
            reply.writeInt(certificate.derLength)
            reply.writeString(certificate.sha256)
        }
        reply.writeString(detail)
        reply.writeString(diagnosticCopyText)
    }

    companion object {
        fun readFromParcel(reply: Parcel): TeeGrantDomainGranteeChainResult {
            val available = reply.readInt() != 0
            val errorKind = runCatching {
                Keystore2PrivateGrantErrorKind.valueOf(reply.readString().orEmpty())
            }.getOrDefault(Keystore2PrivateGrantErrorKind.SERVICE_UNAVAILABLE)
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
                errorKind = errorKind,
                chain = GrantDomainCertificateChain(certificates),
                detail = reply.readString().orEmpty(),
                diagnosticCopyText = reply.readString().orEmpty(),
            )
        }
    }
}
