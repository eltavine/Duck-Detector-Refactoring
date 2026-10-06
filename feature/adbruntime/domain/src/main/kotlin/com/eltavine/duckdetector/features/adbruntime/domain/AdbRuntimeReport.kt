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
    UNSUPPORTED,
}

enum class AdbFindingSeverity {
    HIGH,
}

enum class AdbFindingKind {
    ADB_ROOT_PROPERTY,
    INIT_STOPPED_WITH_ADB_PROTOCOL,
}

data class AdbPropertySnapshot(
    val testHarnessMode: String? = null,
    val initAdbdState: String? = null,
    val sysUsbState: String? = null,
    val serviceAdbRoot: String? = null,
    val serviceAdbRootRequested: Boolean? = null,
    val serviceAdbRootSource: String? = null,
    val serviceAdbRootDetail: String? = null,
)

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
    val state: AdbProbeState = AdbProbeState.UNSUPPORTED,
    val responseKind: AdbProtocolResponseKind? = null,
    val detail: String? = null,
) {
    val confirmed: Boolean
        get() = state == AdbProbeState.OBSERVED && responseKind != null
}

data class AdbRuntimeSample(
    val usbDebuggingEnabled: Boolean? = null,
    val wirelessDebuggingEnabled: Boolean? = null,
    val debuggingFeaturesRestricted: Boolean? = null,
    val properties: AdbPropertySnapshot = AdbPropertySnapshot(),
    val usb: UsbRuntimeSnapshot = UsbRuntimeSnapshot(AdbProbeState.UNAVAILABLE),
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

data class AdbRuntimeFinding(
    val kind: AdbFindingKind,
    val severity: AdbFindingSeverity,
    val detail: String,
)

/** What one ADB runtime scan observed, before the domain layer correlates the sources. */
data class AdbRuntimeReport(
    val stage: AdbRuntimeStage,
    val platformApiLevel: Int? = null,
    val samples: List<AdbRuntimeSample>,
    val mdns: AdbMdnsSnapshot,
    val mdnsSamples: List<AdbMdnsSnapshot> = emptyList(),
    val probed: Boolean,
    val unavailableReason: String? = null,
    val errorMessage: String? = null,
) {
    companion object {
        fun loading(): AdbRuntimeReport = AdbRuntimeReport(
            stage = AdbRuntimeStage.LOADING,
            platformApiLevel = null,
            samples = emptyList(),
            mdns = AdbMdnsSnapshot(AdbProbeState.UNAVAILABLE),
            mdnsSamples = emptyList(),
            probed = false,
        )

        fun failed(message: String): AdbRuntimeReport = AdbRuntimeReport(
            stage = AdbRuntimeStage.FAILED,
            platformApiLevel = null,
            samples = emptyList(),
            mdns = AdbMdnsSnapshot(AdbProbeState.UNAVAILABLE),
            mdnsSamples = emptyList(),
            probed = false,
            errorMessage = message,
        )
    }
}
