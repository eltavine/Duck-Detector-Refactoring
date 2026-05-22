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
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.resume

class TeeGrantDomainGranteeManager(
    context: Context? = null,
    private val serviceClass: Class<out Service> = TeeGrantDomainGranteeService::class.java,
) {

    private val appContext = context?.applicationContext

    suspend fun openSession(): TeeGrantDomainGranteeSessionResult {
        val context = appContext ?: return TeeGrantDomainGranteeSessionResult(
            detail = "Grant-domain grantee context unavailable.",
        )
        return withTimeoutOrNull(DETECTION_TIMEOUT_MS) {
            bindGrantee(context)
        } ?: TeeGrantDomainGranteeSessionResult(
            detail = "Grant-domain isolated grantee timed out.",
        )
    }

    private suspend fun bindGrantee(context: Context): TeeGrantDomainGranteeSessionResult =
        suspendCancellableCoroutine { continuation ->
            var bound = false
            lateinit var connection: ServiceConnection

            fun finish(
                result: TeeGrantDomainGranteeSessionResult,
                keepBoundForSession: Boolean = false,
            ) {
                if (!continuation.isActive) {
                    return
                }
                if (bound && !keepBoundForSession) {
                    runCatching { context.unbindService(connection) }
                    bound = false
                }
                continuation.resume(result)
            }

            connection = object : ServiceConnection {
                override fun onServiceConnected(
                    name: ComponentName?,
                    service: IBinder?,
                ) {
                    if (service == null) {
                        finish(
                            TeeGrantDomainGranteeSessionResult(
                                detail = "Grant-domain isolated grantee returned a null binder.",
                            ),
                        )
                        return
                    }
                    runCatching {
                        val proxy = TeeGrantDomainGranteeProxy(service)
                        val uid = proxy.getUid()
                        TeeGrantDomainGranteeSession(
                            context = context,
                            connection = connection,
                            proxy = proxy,
                            uid = uid,
                            bound = true,
                        )
                    }.onSuccess { session ->
                        bound = false
                        finish(
                            TeeGrantDomainGranteeSessionResult(
                                available = true,
                                session = session,
                                detail = "Grant-domain isolated grantee bound with uid=${session.uid}.",
                            ),
                            keepBoundForSession = true,
                        )
                    }.onFailure { throwable ->
                        finish(
                            TeeGrantDomainGranteeSessionResult(
                                detail = "Grant-domain isolated grantee handshake failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
                            ),
                        )
                    }
                }

                override fun onServiceDisconnected(name: ComponentName?) = Unit
            }

            val intent = Intent(context, serviceClass)
            bound = runCatching {
                bindIsolatedService(context, intent, connection)
            }.getOrDefault(false)
            if (!bound) {
                finish(
                    TeeGrantDomainGranteeSessionResult(
                        detail = "Grant-domain isolated grantee could not be bound.",
                    ),
                )
            }

            continuation.invokeOnCancellation {
                if (bound) {
                    runCatching { context.unbindService(connection) }
                    bound = false
                }
            }
        }

    companion object {
        private const val DETECTION_TIMEOUT_MS = 6_000L

        private fun bindIsolatedService(
            context: Context,
            intent: Intent,
            connection: ServiceConnection,
        ): Boolean {
            return context.bindIsolatedService(
                intent,
                Context.BIND_AUTO_CREATE,
                "duck_grant_domain_${System.nanoTime()}",
                Runnable::run,
                connection,
            )
        }
    }
}

data class TeeGrantDomainGranteeSessionResult(
    val available: Boolean = false,
    val session: TeeGrantDomainGranteeSession? = null,
    val detail: String = "",
)

class TeeGrantDomainGranteeSession(
    private val context: Context,
    private val connection: ServiceConnection,
    private val proxy: TeeGrantDomainGranteeProxy,
    val uid: Int,
    private var bound: Boolean,
) : AutoCloseable {

    fun readGrantedCertificateChain(grantId: Long): TeeGrantDomainGranteeChainResult {
        return runCatching {
            proxy.readGrantedCertificateChain(grantId)
        }.getOrElse { throwable ->
            TeeGrantDomainGranteeChainResult(
                available = false,
                detail = "Grant-domain grantee binder call failed: ${GrantDomainFullChainSplitProbe.describeThrowable(throwable)}",
            )
        }
    }

    override fun close() {
        if (bound) {
            runCatching { context.unbindService(connection) }
            bound = false
        }
    }
}
