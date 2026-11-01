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

/*
 * init records `init.svc.adbd=stopped` only after it unlinks the service socket, and the daemon
 * closes its JDWP listener when that process dies, so neither socket can outlive the state the
 * property reports. Each is compared on its own and reported as its own finding
 * (EVIDENCE.md, "init service socket" and "JDWP control socket").
 *
 * Settings express control intent and USB_STATE / sys.usb.state describe the gadget; AOSP lets both
 * lag the daemon on every release from Android 10 to 17, so neither is compared with init as danger
 * (EVIDENCE.md, "Settings and lifecycle context" and "USB runtime broadcast"). service.adb.root is
 * left to the System Properties detector (EVIDENCE.md, "ADB property context").
 */
fun AdbRuntimeReport.findings(): List<AdbRuntimeFinding> {
    if (stage != AdbRuntimeStage.READY || samples.size < 2) {
        return emptyList()
    }
    if (!samples.all { sample -> sample.properties.daemonState == AdbDaemonState.STOPPED }) {
        return emptyList()
    }
    val endpoint = stableProtocolEndpoint()
    return buildList {
        if (endpoint != null) {
            add(AdbRuntimeFinding(AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL, AdbFindingSeverity.HIGH, endpoint))
        }
        if (samples.all { sample -> sample.initSocket.present == true }) {
            add(AdbRuntimeFinding(AdbFindingKind.INIT_STOPPED_WITH_ADB_INIT_SOCKET, AdbFindingSeverity.HIGH))
        }
        if (samples.all { sample -> sample.jdwpSocket.abstractPresent == true }) {
            add(AdbRuntimeFinding(AdbFindingKind.INIT_STOPPED_WITH_ADB_JDWP_SOCKET, AdbFindingSeverity.HIGH))
        }
    }
}


fun AdbRuntimeReport.isAdbActive(): Boolean {
    if (stage != AdbRuntimeStage.READY) {
        return false
    }
    val latest = samples.lastOrNull()
        ?: return latestMdns.localServiceObserved

    /*
     * A readable ADB_ENABLED=1 is not authoritative in two AOSP cases: AdbService cannot synchronise
     * Settings while DISALLOW_DEBUGGING_FEATURES is active, and from Android 13 Test Harness Mode
     * writes ADB_ENABLED=1 without the ordinary USB transport (EVIDENCE.md, "Settings and lifecycle
     * context"). Runtime, property and mDNS evidence still count in both cases.
     */
    val settingsUsable = latest.debuggingFeaturesRestricted == false
    val usbSettingActive = settingsUsable &&
        latest.usbDebuggingEnabled == true &&
        !(platformApiLevel != null &&
            platformApiLevel >= ANDROID_13_API &&
            latest.properties.testHarnessEnabled)
    val wifiSettingActive = settingsUsable && latest.wirelessDebuggingEnabled == true

    return usbSettingActive ||
        wifiSettingActive ||
        latest.properties.daemonState == AdbDaemonState.RUNNING ||
        latest.initSocket.present == true ||
        latest.jdwpSocket.abstractPresent == true ||
        latest.usb.adbFunctionEnabled ||
        latest.properties.usbAdbFunctionEnabled == true ||
        latestMdns.localServiceObserved
}

/*
 * Both discovery passes must confirm the same service kind, address and port: adbd can restart and
 * advertise another port between them, and one answer alone may belong to a transition.
 */
private fun AdbRuntimeReport.stableProtocolEndpoint(): AdbProtocolEndpoint? {
    if (mdnsSamples.size < 2) {
        return null
    }
    val endpoints = mdnsSamples.map { snapshot -> snapshot.confirmedEndpoint() ?: return null }
    val latest = endpoints.last()
    return latest.takeIf { endpoints.all { endpoint -> endpoint.isSameListener(latest) } }
}

private fun AdbMdnsSnapshot.confirmedEndpoint(): AdbProtocolEndpoint? {
    if (!localServiceObserved || !protocol.confirmed) {
        return null
    }
    return AdbProtocolEndpoint(
        serviceKind = serviceKind ?: return null,
        address = address ?: return null,
        port = port ?: return null,
        responseKind = protocol.responseKind ?: return null,
    )
}

private fun AdbProtocolEndpoint.isSameListener(other: AdbProtocolEndpoint): Boolean =
    serviceKind == other.serviceKind && address == other.address && port == other.port

private const val ANDROID_13_API = 33
