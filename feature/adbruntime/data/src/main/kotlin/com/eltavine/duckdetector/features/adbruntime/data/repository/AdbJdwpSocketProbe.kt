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

package com.eltavine.duckdetector.features.adbruntime.data.repository

import android.system.Os
import com.eltavine.duckdetector.features.adbruntime.domain.AdbJdwpSocketSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState

/**
 * adbd binds this abstract SOCK_SEQPACKET listener itself so that a debuggable process can hand it
 * the socket a JDWP debugger will talk over, which makes it the JDWP control channel rather than a
 * command channel for adbd. `adbconnection_listen()` in packages/modules/adb/libs/adbconnection
 * binds the name and calls listen(4), unchanged from Android 10 to 17. The source writes the address
 * as "\0jdwp-control" because a leading zero byte is what marks an abstract name in sun_path, and
 * both /proc/net/unix and the AOSP comment spell that byte as '@', so `@jdwp-control` names the same
 * socket. No abstract socket is called `adbd`: init owns /dev/socket/adbd and passes the descriptor
 * to adbd as ANDROID_SOCKET_adbd.
 *
 * The socket table would show it, but /proc/net/unix is closed to ordinary apps. connect() needs no
 * such permission: the kernel resolves the name and type first, so a missing listener fails with
 * ECONNREFUSED before any policy check, while a matching one reaches SELinux, where
 * `allow appdomain adbd:unix_stream_socket connectto` ships on every release from Android 10. A
 * running adbd therefore accepts the connect, and EACCES appears only where an OEM removed that
 * grant. Both count as presence; only a refusal means the listener is gone (EVIDENCE.md, "JDWP
 * control socket"). Only a connect and a close are issued; no bytes are sent, so no JDWP handshake
 * starts.
 *
 * A refusal is absence. Faking the opposite takes root: binding the same name, or removing the
 * listener, both need privileges this process does not hold.
 */
internal fun classifyAbstractConnect(errno: Int?): AdbProbeState = when (errno) {
    0 -> AdbProbeState.OBSERVED
    // The LSM check runs after the name and type matched, so a denial proves the listener exists.
    AdbStatErrno.EACCES, AdbStatErrno.EPERM -> AdbProbeState.OBSERVED
    AdbStatErrno.ECONNREFUSED, AdbStatErrno.ENOENT -> AdbProbeState.NOT_OBSERVED
    // Nonblocking connect can return EAGAIN when the listen backlog is full; it is not absence.
    AdbStatErrno.EAGAIN, AdbStatErrno.EINPROGRESS, AdbStatErrno.EINTR ->
        AdbProbeState.UNAVAILABLE
    else -> AdbProbeState.UNAVAILABLE
}

internal class AdbJdwpSocketProbe(
    private val bridge: AdbJdwpSocketBridge = AdbJdwpSocketBridge(),
) {
    fun probe(): AdbJdwpSocketSnapshot {
        val abstractErrno = bridge.connectErrno(ABSTRACT_NAME, abstractName = true)
        return AdbJdwpSocketSnapshot(
            abstract = classifyAbstractConnect(abstractErrno),
            detail = "abstract(@$ABSTRACT_NAME)=${errnoLabel(abstractErrno)}",
        )
    }

    private fun errnoLabel(errno: Int?): String = when (errno) {
        null -> "unknown"
        0 -> "connected"
        else -> runCatching { Os.strerror(errno) }.getOrDefault("errno=$errno")
    }

    companion object {
        const val ABSTRACT_NAME = "jdwp-control"
    }
}
