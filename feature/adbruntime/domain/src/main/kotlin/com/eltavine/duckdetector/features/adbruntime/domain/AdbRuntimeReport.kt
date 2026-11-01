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

package com.eltavine.duckdetector.features.adbruntime.domain

enum class AdbRuntimeStage {
    LOADING,
    READY,
    FAILED,
}

enum class AdbProbeState {
    OBSERVED,
    NOT_OBSERVED,
    UNAVAILABLE,
    PERMISSION_REQUIRED,
    NOT_PROBED,
}

enum class AdbFindingSeverity {
    HIGH,
}

enum class AdbFindingKind {
    INIT_STOPPED_WITH_ADB_PROTOCOL,
    INIT_STOPPED_WITH_ADB_INIT_SOCKET,
    INIT_STOPPED_WITH_ADB_JDWP_SOCKET,
}

enum class AdbDaemonState {
    RUNNING,
    STOPPED,
    OTHER,
}

data class AdbPropertySnapshot(
    val testHarnessMode: String? = null,
    val initAdbdState: String? = null,
    val sysUsbState: String? = null,
) {
    val daemonState: AdbDaemonState?
        get() = when {
            initAdbdState == null -> null
            initAdbdState.equals("running", ignoreCase = true) -> AdbDaemonState.RUNNING
            initAdbdState.equals("stopped", ignoreCase = true) -> AdbDaemonState.STOPPED
            else -> AdbDaemonState.OTHER
        }

    val testHarnessEnabled: Boolean
        get() = testHarnessMode == "1"

    val usbAdbFunctionEnabled: Boolean?
        get() = sysUsbState?.split(',')?.any { function -> function.trim().equals("adb", ignoreCase = true) }
}

data class UsbRuntimeSnapshot(
    val state: AdbProbeState,
    val connected: Boolean? = null,
    val configured: Boolean? = null,
    val functions: Set<String> = emptySet(),
    val detail: String? = null,
) {
    val adbFunctionEnabled: Boolean get() = "adb" in functions
}

enum class AdbMdnsServiceKind {
    LEGACY_TCP,
    TLS_CONNECT,
}

enum class AdbProtocolResponseKind {
    AUTH_TOKEN,
    CONNECT,
    START_TLS,
}

data class AdbProtocolSnapshot(
    val state: AdbProbeState = AdbProbeState.NOT_PROBED,
    val responseKind: AdbProtocolResponseKind? = null,
    val detail: String? = null,
) {
    val confirmed: Boolean
        get() = state == AdbProbeState.OBSERVED && responseKind != null
}

/** How init's per-service socket path resolved, as far as this process could observe it. */
enum class AdbSocketPresence {
    /** stat() succeeded, so the inode exists and its label allowed the query. */
    PRESENT,

    /** stat() was refused for the socket inode itself while a sibling control path was absent. */
    PRESENT_DENIED,
    ABSENT,
    UNKNOWN,
}

/**
 * init creates one socket per declared `socket` line when a service starts and unlinks it after that
 * service's process reaps (EVIDENCE.md, "init service socket"). adbd therefore has
 * /dev/socket/adbd only while its process lives.
 */
data class AdbInitSocketSnapshot(
    val state: AdbProbeState,
    val presence: AdbSocketPresence = AdbSocketPresence.UNKNOWN,
    val detail: String? = null,
) {
    val present: Boolean?
        get() = when (presence) {
            AdbSocketPresence.PRESENT, AdbSocketPresence.PRESENT_DENIED -> true
            AdbSocketPresence.ABSENT -> false
            AdbSocketPresence.UNKNOWN -> null
        }
}

/**
 * adbd binds the JDWP control socket `@jdwp-control` itself (packages/modules/adb/libs/adbconnection)
 * so that a debuggable process can hand adbd the socket a debugger will use; it is a JDWP feature,
 * not a command channel for adbd. Its presence is liveness evidence that does not depend on init's
 * socket table (EVIDENCE.md, "JDWP control socket").
 */
data class AdbJdwpSocketSnapshot(
    val abstract: AdbProbeState = AdbProbeState.UNAVAILABLE,
    val detail: String? = null,
) {
    val abstractPresent: Boolean?
        get() = when (abstract) {
            AdbProbeState.OBSERVED -> true
            AdbProbeState.NOT_OBSERVED -> false
            else -> null
        }
}

data class AdbRuntimeSample(
    val usbDebuggingEnabled: Boolean? = null,
    val wirelessDebuggingEnabled: Boolean? = null,
    val debuggingFeaturesRestricted: Boolean? = null,
    val properties: AdbPropertySnapshot = AdbPropertySnapshot(),
    val usb: UsbRuntimeSnapshot = UsbRuntimeSnapshot(AdbProbeState.UNAVAILABLE),
    val initSocket: AdbInitSocketSnapshot = AdbInitSocketSnapshot(AdbProbeState.UNAVAILABLE),
    val jdwpSocket: AdbJdwpSocketSnapshot = AdbJdwpSocketSnapshot(),
)

data class AdbMdnsSnapshot(
    val state: AdbProbeState,
    val serviceKind: AdbMdnsServiceKind? = null,
    val serviceName: String? = null,
    val address: String? = null,
    val port: Int? = null,
    val protocol: AdbProtocolSnapshot = AdbProtocolSnapshot(),
    val detail: String? = null,
) {
    val localServiceObserved: Boolean get() = state == AdbProbeState.OBSERVED && port != null
}

/** A local endpoint that answered with the AOSP first packet of the service type it advertised. */
data class AdbProtocolEndpoint(
    val serviceKind: AdbMdnsServiceKind,
    val address: String,
    val port: Int,
    val responseKind: AdbProtocolResponseKind,
)

data class AdbRuntimeFinding(
    val kind: AdbFindingKind,
    val severity: AdbFindingSeverity,
    val endpoint: AdbProtocolEndpoint? = null,
)

/** What one ADB runtime scan observed, before the domain layer correlates the sources. */
data class AdbRuntimeReport(
    val stage: AdbRuntimeStage,
    val platformApiLevel: Int? = null,
    val samples: List<AdbRuntimeSample>,
    /** One entry per discovery pass; the second pass runs only after the first confirmed an endpoint. */
    val mdnsSamples: List<AdbMdnsSnapshot> = emptyList(),
    val probed: Boolean,
    val unavailableReason: String? = null,
    val errorMessage: String? = null,
) {
    val latestMdns: AdbMdnsSnapshot
        get() = mdnsSamples.lastOrNull() ?: AdbMdnsSnapshot(AdbProbeState.NOT_PROBED)

    companion object {
        fun loading(): AdbRuntimeReport = AdbRuntimeReport(
            stage = AdbRuntimeStage.LOADING,
            samples = emptyList(),
            probed = false,
        )

        fun failed(message: String): AdbRuntimeReport = AdbRuntimeReport(
            stage = AdbRuntimeStage.FAILED,
            samples = emptyList(),
            probed = false,
            errorMessage = message,
        )
    }
}
