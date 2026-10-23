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

import android.system.ErrnoException
import android.system.Os
import java.io.File
import com.eltavine.duckdetector.features.adbruntime.domain.AdbInitSocketSnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbSocketPresence

/**
 * The errno values the Linux kernel returns here. They are spelled out because the unit-test
 * android.jar zeroes android.system.OsConstants, which would make every comparison below match.
 */
internal object AdbStatErrno {
    const val EPERM = 1
    const val ENOENT = 2
    const val EINTR = 4
    const val EAGAIN = 11
    const val EACCES = 13
    const val EINPROGRESS = 115
    const val ECONNREFUSED = 111
}

/** What a three-way `stat()` comparison says about one init socket path. */
internal enum class AdbInitSocketObservation {
    PRESENT,
    PRESENT_DENIED,
    ABSENT,
    DIRECTORY_DENIED,
    UNKNOWN,
}

/**
 * init declares `socket adbd seqpacket 660 system system` for `service adbd` in
 * system/core/rootdir/init.usb.rc line 17 on every release from Android 10 to 17. The inode is
 * created while the service starts and removed while it is reaped, before init publishes
 * `init.svc.adbd=stopped`; Android 10 removes it through SocketInfo::Close, Android 11 and later
 * unlink it directly in Service::Reap() (EVIDENCE.md, "init service socket", lists both sites).
 * Applications hold r_dir_perms on /dev/socket but no permission on the adbd_socket label, so a
 * present inode rejects stat() with EACCES while an absent one fails at lookup with ENOENT. A
 * sibling control name that cannot exist separates "the socket is there and its label hides it"
 * from "this process cannot resolve anything in that directory".
 */
internal fun classifyInitSocketStat(
    directoryErrno: Int?,
    targetErrno: Int?,
    controlErrno: Int?,
): AdbInitSocketObservation = when {
    directoryErrno == null || targetErrno == null || controlErrno == null ->
        AdbInitSocketObservation.UNKNOWN
    directoryErrno != 0 -> if (directoryErrno == AdbStatErrno.EACCES || directoryErrno == AdbStatErrno.EPERM) {
        AdbInitSocketObservation.DIRECTORY_DENIED
    } else {
        AdbInitSocketObservation.UNKNOWN
    }
    targetErrno == 0 -> AdbInitSocketObservation.PRESENT
    // Before inferring a denied inode, the control path must fail with ENOENT.
    controlErrno != AdbStatErrno.ENOENT -> if (controlErrno == AdbStatErrno.EACCES || controlErrno == AdbStatErrno.EPERM) {
        AdbInitSocketObservation.DIRECTORY_DENIED
    } else {
        AdbInitSocketObservation.UNKNOWN
    }
    targetErrno == AdbStatErrno.ENOENT -> AdbInitSocketObservation.ABSENT
    targetErrno == AdbStatErrno.EACCES || targetErrno == AdbStatErrno.EPERM ->
        AdbInitSocketObservation.PRESENT_DENIED
    else -> AdbInitSocketObservation.UNKNOWN
}

/**
 * A successful listing is a separate, earlier observation, not proof that a subsequent stat()
 * failure was caused by the inode's SELinux label. Conflicting evidence may be a service restart:
 * never turn such a transition into a stable present/absent or label-denied result.
 */
internal fun resolveInitSocketPresence(
    listedNames: Set<String>?,
    statObservation: AdbInitSocketObservation,
): AdbInitSocketObservation = when {
    listedNames == null -> statObservation
    "adbd" in listedNames -> when (statObservation) {
        AdbInitSocketObservation.PRESENT, AdbInitSocketObservation.PRESENT_DENIED -> statObservation
        else -> AdbInitSocketObservation.UNKNOWN
    }
    else -> when (statObservation) {
        AdbInitSocketObservation.ABSENT -> AdbInitSocketObservation.ABSENT
        else -> AdbInitSocketObservation.UNKNOWN
    }
}

internal object AdbInitSocketProbe {
    const val DIRECTORY = "/dev/socket"
    const val ADBD_PATH = "/dev/socket/adbd"
    const val ADBD_NAME = "adbd"
    private const val CONTROL_PREFIX = "duckdetector_absent_probe_"

    fun read(): AdbInitSocketSnapshot {
        val control = DIRECTORY + "/" + CONTROL_PREFIX + System.nanoTime().toString(16)
        val listed = runCatching { File(DIRECTORY).list()?.toSet() }.getOrNull()
        val directoryErrno = statErrno(DIRECTORY)
        val targetErrno = statErrno(ADBD_PATH)
        val controlErrno = statErrno(control)
        val statObservation = classifyInitSocketStat(directoryErrno, targetErrno, controlErrno)
        val observation = resolveInitSocketPresence(listed, statObservation)
        val detail = "listing=${if (listed == null) "unavailable" else "readable"}" +
            ", directory=${errnoLabel(directoryErrno)}, socket=${errnoLabel(targetErrno)}" +
            ", control=${errnoLabel(controlErrno)}"
        return when (observation) {
            AdbInitSocketObservation.PRESENT -> AdbInitSocketSnapshot(
                AdbProbeState.OBSERVED, AdbSocketPresence.PRESENT,
                "stat($ADBD_PATH) succeeded, confirming the socket path was resolvable. " + detail,
            )

            AdbInitSocketObservation.PRESENT_DENIED -> AdbInitSocketSnapshot(
                AdbProbeState.OBSERVED, AdbSocketPresence.PRESENT_DENIED,
                "stat($ADBD_PATH) was refused on the socket inode while the sibling control path did " +
                    "not exist, so the inode is present and its label hides the attributes. " + detail,
            )

            AdbInitSocketObservation.ABSENT -> AdbInitSocketSnapshot(
                AdbProbeState.NOT_OBSERVED, AdbSocketPresence.ABSENT,
                "The directory could be resolved and no adbd entry or inode was observed. " + detail,
            )

            AdbInitSocketObservation.DIRECTORY_DENIED -> AdbInitSocketSnapshot(
                AdbProbeState.PERMISSION_REQUIRED, AdbSocketPresence.UNKNOWN,
                "This process cannot resolve names in $DIRECTORY, so socket presence is not observable. " +
                    detail,
            )

            AdbInitSocketObservation.UNKNOWN -> AdbInitSocketSnapshot(
                AdbProbeState.UNAVAILABLE, AdbSocketPresence.UNKNOWN,
                "The socket probe produced no interpretable result. " + detail,
            )
        }
    }

    /** 0 on success, errno on failure, null when the call could not be classified. */
    private fun statErrno(path: String): Int? = try {
        Os.stat(path)
        0
    } catch (failure: ErrnoException) {
        failure.errno
    } catch (_: RuntimeException) {
        null
    }

    private fun errnoLabel(errno: Int?): String = when (errno) {
        null -> "unknown"
        0 -> "ok"
        else -> runCatching { Os.strerror(errno) }.getOrDefault("errno=$errno")
    }
}
