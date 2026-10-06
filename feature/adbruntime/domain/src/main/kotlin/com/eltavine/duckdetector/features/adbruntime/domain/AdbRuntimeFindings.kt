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

fun AdbRuntimeReport.findings(): List<AdbRuntimeFinding> {
    if (stage != AdbRuntimeStage.READY || samples.isEmpty()) {
        return emptyList()
    }

    val findings = mutableListOf<AdbRuntimeFinding>()

    if (samples.any { sample -> sample.properties.serviceAdbRootRequested == true }) {
        /*
         * service.adb.root=1 is the explicit "adb root" request/state. AOSP adbd reads this exact
         * property in should_drop_privileges(); on debuggable builds it keeps root privileges
         * instead of dropping them. service.adb.root=0 is the explicit adb-unroot request.
         *
         * Android 10 tag android-10.0.0_r47, system/core commit
         * 1dea9a052b7f214c10a77d5ed6ffd3602722a817, daemon/main.cpp lines 87-106:
         * https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/main.cpp#87
         *
         * Android 16 tag android-16.0.0_r3, packages/modules/adb commit
         * cf10d3798f0847f89820381b541aedfd27a30375, daemon/main.cpp lines 76-95:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/main.cpp#76
         *
         * We report the explicit root request as Danger even when ro.debuggable is not observable
         * or is false. The property proves the privileged ADB request/state.
         */
        findings += AdbRuntimeFinding(
            kind = AdbFindingKind.ADB_ROOT_PROPERTY,
            severity = AdbFindingSeverity.HIGH,
            detail = samples.asReversed()
                .mapNotNull { sample -> sample.properties.serviceAdbRootDetail }
                .firstOrNull()
                ?: "service.adb.root=1 records an explicit ADB root request/state.",
        )
    }

    /*
     * Settings.Global is intentionally NOT compared with init.svc.adbd as a hard contradiction.
     *
     * Android 10 treats ADB_ENABLED as framework/transport control state. setAdbEnabled() stores
     * the value and forwards it to registered IAdbTransport implementations; the setting itself is
     * not daemon-liveness evidence:
     * android-10.0.0_r47, frameworks/base commit
     * dff3deab5d25f8bbfd49abfb423043c9be47b7db, lines 263-278:
     * https://android.googlesource.com/platform/frameworks/base/+/dff3deab5d25f8bbfd49abfb423043c9be47b7db/services/core/java/com/android/server/adb/AdbService.java#263
     *
     * Android 11-15 split daemon ownership across AdbService transport state and the USB gadget
     * application path. Android 11 setUsbConfig() starts/stops the USB transport according to the
     * applied function mask (lines 1894-1905); Android 15 keeps the same pattern at 2494-2505:
     * https://android.googlesource.com/platform/frameworks/base/+/1d9b9ab57d844b18b3b1b4297725141e7788109b/services/usb/java/com/android/server/usb/UsbDeviceManager.java#1894
     * https://android.googlesource.com/platform/frameworks/base/+/396d32905ded85c082232bc510b525c9e372e585/services/usb/java/com/android/server/usb/UsbDeviceManager.java#2494
     *
     * Android 16 removes those UsbDeviceManager startAdbdForTransport/stopAdbdForTransport calls;
     * AdbService directly owns the transport booleans and starts/stops adbd (lines 393-400 and
     * 440-488):
     * android-16.0.0_r3, frameworks/base commit
     * 33b96ce8a122757002e5040ac59824bd7a262e00:
     * https://android.googlesource.com/platform/frameworks/base/+/33b96ce8a122757002e5040ac59824bd7a262e00/services/core/java/com/android/server/adb/AdbService.java#393
     *
     * Across these versions Settings still represents control intent rather than process liveness.
     * Android 13 additionally permits ADB_ENABLED=1 in Test Harness Mode even when the ordinary
     * USB transport boolean is false, and synchronization can be blocked by
     * DISALLOW_DEBUGGING_FEATURES (lines 258-293):
     * android-13.0.0_r83, frameworks/base commit
     * 5c8d1d9774e465bb40d45096b2bc5eba77b261d6:
     * https://android.googlesource.com/platform/frameworks/base/+/5c8d1d9774e465bb40d45096b2bc5eba77b261d6/services/core/java/com/android/server/adb/AdbService.java#258
     *
     * Consequently Settings only contributes to warning-level "ADB active/enabled". Danger
     * requires a runtime surface below to contradict init.svc.adbd.
     */

    /*
     * ACTION_USB_STATE is intentionally NOT a hard contradiction source. Android 10 and Android 16
     * both derive the broadcast function list from getAppliedFunctions() (A10 lines 786-793, A16
     * lines 1193-1201) and publish mConfigured separately (A10 lines 701-718, A16 lines 989-1006):
     *
     * https://android.googlesource.com/platform/frameworks/base/+/dff3deab5d25f8bbfd49abfb423043c9be47b7db/services/usb/java/com/android/server/usb/UsbDeviceManager.java#701
     * https://android.googlesource.com/platform/frameworks/base/+/33b96ce8a122757002e5040ac59824bd7a262e00/services/usb/java/com/android/server/usb/UsbDeviceManager.java#989
     *
     * More importantly, Android 16 configfs reacts to init.svc.adbd=stopped by clearing only
     * sys.usb.ffs.ready (lines 14-15). The ffs.adb link/UDC is created by separate ready=1 actions
     * (for example lines 20-24 and 35-40), so a configured gadget can outlive adbd briefly:
     * https://android.googlesource.com/platform/system/core/+/4deec4059670028cccb7f9f22bb73813ae71c6f3/rootdir/init.usb.configfs.rc#14
     *
     * Therefore USB configured+adb is warning/activity context only. Treating it as Danger would
     * incorrectly equate gadget configuration with daemon liveness.
     */

    if (
        stableAdbProtocolRuntime() &&
        stableContradiction { sample -> sample.properties.initAdbdState.isStopped() }
    ) {
        /*
         * DNS-SD metadata identifies a candidate endpoint but is not identity by itself. The hard
         * signal here is the ADB wire protocol returned by that local endpoint.
         *
         * The probe sends exactly one A_CNXN and reads one response. Android 10 legacy adbd answers
         * with A_CNXN when authentication is not required or A_AUTH/ADB_AUTH_TOKEN when it is.
         *
         * Android 10 tag android-10.0.0_r47, system/core commit
         * 1dea9a052b7f214c10a77d5ed6ffd3602722a817:
         * handle_new_connection() lines 294-307:
         * https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/adb.cpp#294
         * AUTH token generation lines 262-276:
         * https://android.googlesource.com/platform/system/core/+/1dea9a052b7f214c10a77d5ed6ffd3602722a817/adb/daemon/auth.cpp#262
         *
         * Modern Wireless Debugging uses the same ADB framing before TLS. A TLS transport answers
         * that initial A_CNXN with A_STLS, which is the first packet telling the peer to switch to
         * the TLS protocol:
         * android-16.0.0_r3, packages/modules/adb commit
         * cf10d3798f0847f89820381b541aedfd27a30375:
         * TlsServer accepts the secure-connect socket and registers it with use_tls=true at
         * daemon/adb_wifi.cpp lines 127-142:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/adb_wifi.cpp#127
         * send_tls_request() constructs A_STLS/A_STLS_VERSION at adb.cpp lines 318-324:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#318
         * the initial-CNXN handler chooses send_tls_request(t) when t->use_tls at lines 420-430:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#420
         *
         * Sending an RSA public key is what reaches adbd_auth_confirm_key() and the user prompt.
         * The detector never sends that packet:
         * Android 16 tag android-16.0.0_r3, packages/modules/adb commit
         * cf10d3798f0847f89820381b541aedfd27a30375, adb.cpp lines 462-490 and
         * daemon/auth.cpp lines 311-318:
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/adb.cpp#462
         * https://android.googlesource.com/platform/packages/modules/adb/+/cf10d3798f0847f89820381b541aedfd27a30375/daemon/auth.cpp#311
         *
         * Two observations of the same local endpoint are required, so a stale advertisement or a
         * listener replaced during the debounce interval cannot manufacture a hard contradiction.
         */
        findings += AdbRuntimeFinding(
            kind = AdbFindingKind.INIT_STOPPED_WITH_ADB_PROTOCOL,
            severity = AdbFindingSeverity.HIGH,
            detail = buildString {
                val endpoint = mdnsSamples.last()
                append("The local ")
                append(
                    when (endpoint.serviceKind) {
                        AdbMdnsServiceKind.LEGACY_TCP -> "legacy ADB"
                        AdbMdnsServiceKind.TLS_CONNECT -> "Wireless ADB secure-connect"
                        null -> "ADB"
                    },
                )
                append(" endpoint ")
                append(endpoint.address ?: "on this device")
                append(':')
                append(endpoint.port)
                append(" answered the expected ADB ")
                append(endpoint.protocol.responseKind?.name ?: "protocol")
                append(" handshake while init.svc.adbd remained stopped.")
            },
        )
    }

    return findings
}

fun AdbRuntimeReport.isAdbActive(): Boolean {
    if (stage != AdbRuntimeStage.READY) {
        return false
    }
    val latest = samples.lastOrNull()
        ?: return mdns.localServiceObserved

    /*
     * Settings normally describe user/framework ADB enablement, so they contribute to Warning.
     * Two AOSP exceptions make a raw "1" non-authoritative:
     *
     * 1. AdbService catches SecurityException while synchronizing the Settings values when
     *    DISALLOW_DEBUGGING_FEATURES is active.
     *    android-11.0.0_r48, frameworks/base commit
     *    1d9b9ab57d844b18b3b1b4297725141e7788109b, lines 255-266:
     *    https://android.googlesource.com/platform/frameworks/base/+/1d9b9ab57d844b18b3b1b4297725141e7788109b/services/core/java/com/android/server/adb/AdbService.java#255
     *
     * 2. Android 13+ deliberately writes ADB_ENABLED=1 in Test Harness Mode even when the normal
     *    USB transport boolean is false.
     *    android-13.0.0_r83, frameworks/base commit
     *    5c8d1d9774e465bb40d45096b2bc5eba77b261d6, lines 258-293:
     *    https://android.googlesource.com/platform/frameworks/base/+/5c8d1d9774e465bb40d45096b2bc5eba77b261d6/services/core/java/com/android/server/adb/AdbService.java#258
     *
     * In either case runtime/property/mDNS evidence can still produce Warning independently.
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
        mdns.localServiceObserved
}

private inline fun AdbRuntimeReport.stableContradiction(
    predicate: (AdbRuntimeSample) -> Boolean,
): Boolean = samples.size >= 2 && samples.all(predicate)

/*
 * A protocol response is stronger than the DNS-SD service name. Require the same service kind and
 * endpoint twice because adbd may restart and re-advertise on another port between samples.
 */
private fun AdbRuntimeReport.stableAdbProtocolRuntime(): Boolean {
    if (mdnsSamples.size < 2) {
        return false
    }
    val endpoints = mdnsSamples.mapNotNull { snapshot ->
        if (
            !snapshot.localServiceObserved ||
            !snapshot.protocol.confirmed ||
            snapshot.serviceKind == null ||
            snapshot.address == null ||
            snapshot.port == null
        ) {
            null
        } else {
            Triple(snapshot.serviceKind, snapshot.address, snapshot.port)
        }
    }
    return endpoints.size == mdnsSamples.size && endpoints.distinct().size == 1
}

private fun String?.isStopped(): Boolean = equals("stopped", ignoreCase = true)

private fun String?.containsFunction(function: String): Boolean =
    orEmpty().split(',').any { it.trim().equals(function, ignoreCase = true) }

private const val ANDROID_13_API = 33
