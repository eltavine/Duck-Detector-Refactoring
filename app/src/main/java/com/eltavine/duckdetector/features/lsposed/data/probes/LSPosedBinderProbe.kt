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

package com.eltavine.duckdetector.features.lsposed.data.probes

import android.os.DeadObjectException
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignal
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalGroup
import com.eltavine.duckdetector.features.lsposed.domain.LSPosedSignalSeverity
import java.lang.reflect.Method

data class LSPosedBinderProbeResult(
    val signals: List<LSPosedSignal>,
    val hitCount: Int,
)

class LSPosedBinderProbe {

    @Suppress("PrivateApi")
    fun run(): LSPosedBinderProbeResult {
        val serviceManagerClass = runCatching {
            Class.forName("android.os.ServiceManager")
        }.getOrNull() ?: return LSPosedBinderProbeResult(emptyList(), 0)
        val getServiceMethod = runCatching {
            serviceManagerClass.getMethod("getService", String::class.java)
        }.getOrNull() ?: return LSPosedBinderProbeResult(emptyList(), 0)

        val signals = buildList {
            addAll(probeActivityBridge(getServiceMethod))
            addAll(probeSerialBridge(getServiceMethod))
        }
        return LSPosedBinderProbeResult(
            signals = signals,
            hitCount = signals.size,
        )
    }

    private fun probeActivityBridge(
        getServiceMethod: Method,
    ): List<LSPosedSignal> {
        val binder = runCatching {
            getServiceMethod.invoke(null, "activity") as? IBinder
        }.getOrNull() ?: return emptyList()

        var data: Parcel? = null
        var reply: Parcel? = null
        return try {
            data = Parcel.obtain()
            reply = Parcel.obtain()
            data.writeInterfaceToken(BRIDGE_SERVICE_DESCRIPTOR)
            data.writeInt(BRIDGE_ACTION_GET_BINDER)
            data.writeString("")

            val transactResult = binder.transact(BRIDGE_TRANSACTION_CODE, data, reply, 0)
            if (!transactResult) {
                emptyList()
            } else {
                val detail = buildString {
                    appendLine("Service: activity")
                    appendLine("Transaction: $BRIDGE_TRANSACTION_CODE")
                    append("Interface token: $BRIDGE_SERVICE_DESCRIPTOR")
                }
                reply.setDataPosition(0)
                val replyDetail = runCatching {
                    reply.readException()
                    if (reply.readStrongBinder() != null) {
                        "Binder returned"
                    } else {
                        "Reply accepted"
                    }
                }.getOrElse {
                    "Reply anomaly: ${it.javaClass.simpleName}"
                }
                listOf(
                    LSPosedSignal(
                        id = "binder_activity_bridge",
                        label = "Activity service bridge",
                        value = replyDetail,
                        group = LSPosedSignalGroup.BINDER,
                        severity = LSPosedSignalSeverity.DANGER,
                        detail = detail,
                        detailMonospace = true,
                    ),
                )
            }
        } catch (_: DeadObjectException) {
            emptyList()
        } catch (security: SecurityException) {
            security.message
                ?.takeIf(::containsFrameworkToken)
                ?.let { message ->
                    listOf(
                        LSPosedSignal(
                            id = "binder_activity_exception",
                            label = "Activity bridge exception",
                            value = "LSPosed ref",
                            group = LSPosedSignalGroup.BINDER,
                            severity = LSPosedSignalSeverity.DANGER,
                            detail = message,
                            detailMonospace = true,
                        ),
                    )
                }
                ?: emptyList()
        } catch (throwable: Throwable) {
            throwable.message
                ?.takeIf(::containsFrameworkToken)
                ?.let { message ->
                    listOf(
                        LSPosedSignal(
                            id = "binder_activity_throwable",
                            label = "Activity bridge throwable",
                            value = "Review",
                            group = LSPosedSignalGroup.BINDER,
                            severity = LSPosedSignalSeverity.WARNING,
                            detail = message,
                            detailMonospace = true,
                        ),
                    )
                }
                ?: emptyList()
        } finally {
            data?.recycle()
            reply?.recycle()
        }
    }

    private fun probeSerialBridge(
        getServiceMethod: Method,
    ): List<LSPosedSignal> {
        val binder = runCatching {
            getServiceMethod.invoke(null, "serial") as? IBinder
        }.getOrNull() ?: return emptyList()

        val signals = mutableListOf<LSPosedSignal>()
        runCatching { binder.interfaceDescriptor }
            .getOrNull()
            ?.takeIf(::containsFrameworkToken)
            ?.let { descriptor ->
                signals += LSPosedSignal(
                    id = "binder_serial_descriptor",
                    label = "Serial service descriptor",
                    value = "Hook token",
                    group = LSPosedSignalGroup.BINDER,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = descriptor,
                    detailMonospace = true,
                )
            }

        var data: Parcel? = null
        var reply: Parcel? = null
        try {
            data = Parcel.obtain()
            reply = Parcel.obtain()
            data.writeInt(Process.myUid())
            data.writeInt(Process.myPid())
            data.writeString("duckdetector_probe")

            val transactResult = binder.transact(BRIDGE_TRANSACTION_CODE, data, reply, 0)
            if (transactResult) {
                signals += LSPosedSignal(
                    id = "binder_serial_bridge",
                    label = "Serial service bridge",
                    value = "Responded",
                    group = LSPosedSignalGroup.BINDER,
                    severity = LSPosedSignalSeverity.DANGER,
                    detail = buildString {
                        appendLine("Service: serial")
                        appendLine("Transaction: $BRIDGE_TRANSACTION_CODE")
                        append("Unexpected Binder bridge response from serial service.")
                    },
                    detailMonospace = true,
                )
            }
        } catch (_: DeadObjectException) {
            Unit
        } catch (security: SecurityException) {
            security.message
                ?.takeIf(::containsFrameworkToken)
                ?.let { message ->
                    signals += LSPosedSignal(
                        id = "binder_serial_exception",
                        label = "Serial bridge exception",
                        value = "LSPosed ref",
                        group = LSPosedSignalGroup.BINDER,
                        severity = LSPosedSignalSeverity.DANGER,
                        detail = message,
                        detailMonospace = true,
                    )
                }
        } catch (throwable: Throwable) {
            throwable.message
                ?.takeIf(::containsFrameworkToken)
                ?.let { message ->
                    signals += LSPosedSignal(
                        id = "binder_serial_throwable",
                        label = "Serial bridge throwable",
                        value = "Review",
                        group = LSPosedSignalGroup.BINDER,
                        severity = LSPosedSignalSeverity.WARNING,
                        detail = message,
                        detailMonospace = true,
                    )
                }
        } finally {
            data?.recycle()
            reply?.recycle()
        }

        return signals
    }

    private fun containsFrameworkToken(text: String): Boolean {
        val lower = text.lowercase()
        return FRAMEWORK_TOKENS.any { token -> lower.contains(token) }
    }

    private companion object {
        private const val BRIDGE_TRANSACTION_CODE = 1598837584
        private const val BRIDGE_SERVICE_DESCRIPTOR = "LSPosed"
        private const val BRIDGE_ACTION_GET_BINDER = 2

        private val FRAMEWORK_TOKENS = listOf(
            "lsposed",
            "lspd",
            "xposed",
            "lsplant",
        )
    }
}
