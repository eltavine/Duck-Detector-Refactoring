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
 * The only hard contradiction is a protocol-confirmed ADB endpoint against init.svc.adbd. Settings
 * express control intent and USB_STATE / sys.usb.state describe the gadget; AOSP lets both lag the
 * daemon on every release from Android 10 to 17, so neither is compared with init as danger
 * (EVIDENCE.md, "Settings and lifecycle context" and "USB runtime broadcast"). service.adb.root is
 * left to the System Properties detector (EVIDENCE.md, "ADB property context").
 */
fun AdbRuntimeReport.findings(): List<AdbRuntimeFinding> {
    if (stage != AdbRuntimeStage.READY || samples.size < 2) {
        return emptyList()
    }
    if (!samples.all { sample -> sample.properties.initAdbdState.isStopped() }) {
        return emptyList()
    }
    val endpoint = stableProtocolEndpoint() ?: return emptyList()
    return listOf(
        AdbRuntimeFinding(
            kind = AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL,
            severity = AdbFindingSeverity.HIGH,
            endpoint = endpoint,
        ),
    )
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
            latest.properties.testHarnessMode == "1")
    val wifiSettingActive = settingsUsable && latest.wirelessDebuggingEnabled == true

    return usbSettingActive ||
        wifiSettingActive ||
        latest.properties.initAdbdState.equals("running", ignoreCase = true) ||
        latest.usb.adbFunctionEnabled ||
        latest.properties.sysUsbState.containsFunction("adb") ||
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

private fun String?.isStopped(): Boolean = equals("stopped", ignoreCase = true)

private fun String?.containsFunction(function: String): Boolean =
    orEmpty().split(',').any { it.trim().equals(function, ignoreCase = true) }

private const val ANDROID_13_API = 33
