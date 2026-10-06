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

import android.content.Context
import android.content.IntentFilter
import android.os.UserManager
import android.provider.Settings
import com.eltavine.duckdetector.capability.systemproperties.data.SystemPropertyReadUtils
import com.eltavine.duckdetector.capability.systemproperties.domain.MultiSourcePropertyRead
import com.eltavine.duckdetector.capability.systemproperties.domain.SystemPropertyCategory
import com.eltavine.duckdetector.capability.systemproperties.domain.assessAdbRootProperty
import com.eltavine.duckdetector.features.adbruntime.domain.AdbProbeState
import com.eltavine.duckdetector.features.adbruntime.domain.AdbPropertySnapshot
import com.eltavine.duckdetector.features.adbruntime.domain.AdbRuntimeSample
import com.eltavine.duckdetector.features.adbruntime.domain.UsbRuntimeSnapshot

internal class AdbStateProbe(
    private val context: Context,
    private val propertyReads: SystemPropertyReadUtils = SystemPropertyReadUtils(),
) {
    fun collect(): AdbRuntimeSample = AdbRuntimeSample(
        usbDebuggingEnabled = readGlobalBoolean(ADB_ENABLED),
        wirelessDebuggingEnabled = readGlobalBoolean(ADB_WIFI_ENABLED),
        debuggingFeaturesRestricted = readDebuggingRestriction(),
        properties = readProperties(),
        usb = readUsbState(),
    )

    private fun readGlobalBoolean(name: String): Boolean? = runCatching {
        Settings.Global.getString(context.contentResolver, name)?.trim()?.let { value ->
            when (value) {
                "1" -> true
                "0" -> false
                else -> null
            }
        }
    }.getOrNull()

    /**
     * AOSP AdbService catches SecurityException when synchronizing ADB_ENABLED while
     * DISALLOW_DEBUGGING_FEATURES is active. In that case Settings may be stale and must not be
     * treated as a faithful mirror of the transport state.
     *
     * Android 11 reference (tag android-11.0.0_r48, commit 1d9b9ab57d844b18b3b1b4297725141e7788109b):
     * Settings sync catches SecurityException and names DISALLOW_DEBUGGING_FEATURES at lines 261-266:
     * https://android.googlesource.com/platform/frameworks/base/+/1d9b9ab57d844b18b3b1b4297725141e7788109b/services/core/java/com/android/server/adb/AdbService.java#261
     *
     * UserManager.hasUserRestriction() is public for the current user:
     * Android 10 tag android-10.0.0_r47, lines 1944-1963:
     * https://android.googlesource.com/platform/frameworks/base/+/dff3deab5d25f8bbfd49abfb423043c9be47b7db/core/java/android/os/UserManager.java#1944
     */
    private fun readDebuggingRestriction(): Boolean? = runCatching {
        context.getSystemService(UserManager::class.java)
            .hasUserRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES)
    }.getOrNull()

    private fun readProperties(): AdbPropertySnapshot {
        val nativeSnapshot = propertyReads.collectNativeSnapshot(PROPERTY_NAMES)
        val cache = linkedMapOf<String, MultiSourcePropertyRead>()

        fun readRaw(name: String): MultiSourcePropertyRead =
            propertyReads.readProperty(
                property = name,
                category = SystemPropertyCategory.SECURITY_CORE,
                cache = cache,
                nativeSnapshot = nativeSnapshot,
            )

        fun read(name: String): String? =
            readRaw(name).preferredValue.trim().ifBlank { null }

        val adbRootRead = readRaw(SERVICE_ADB_ROOT)
        val debuggableRead = readRaw(RO_DEBUGGABLE)
        val adbRootAssessment = assessAdbRootProperty(adbRootRead, debuggableRead)

        return AdbPropertySnapshot(
            testHarnessMode = read(PERSIST_SYS_TEST_HARNESS),
            initAdbdState = read(INIT_SVC_ADBD),
            sysUsbState = read(SYS_USB_STATE),
            serviceAdbRoot = adbRootAssessment?.value,
            serviceAdbRootRequested = adbRootAssessment?.rootRequested,
            serviceAdbRootSource = adbRootAssessment?.source?.name,
            serviceAdbRootDetail = adbRootAssessment?.detail,
        )
    }

    /**
     * ACTION_USB_STATE is a sticky framework snapshot, not a direct adbd process probe.
     * UsbDeviceManager publishes "connected", "configured", and applied function names. Even a
     * configured adb gadget is kept at warning/context severity because configfs can clear
     * sys.usb.ffs.ready when adbd stops without tearing the gadget links down in that same trigger.
     *
     * Android 10 tag android-10.0.0_r47, frameworks/base commit
     * dff3deab5d25f8bbfd49abfb423043c9be47b7db:
     * broadcast extras are built at lines 701-718 and ADB is added by getAppliedFunctions()
     * at lines 786-793:
     * https://android.googlesource.com/platform/frameworks/base/+/dff3deab5d25f8bbfd49abfb423043c9be47b7db/services/usb/java/com/android/server/usb/UsbDeviceManager.java#701
     *
     * Android 16 tag android-16.0.0_r3, frameworks/base commit
     * 33b96ce8a122757002e5040ac59824bd7a262e00:
     * broadcast extras are at lines 989-1006 and getAppliedFunctions() at lines 1193-1201:
     * https://android.googlesource.com/platform/frameworks/base/+/33b96ce8a122757002e5040ac59824bd7a262e00/services/usb/java/com/android/server/usb/UsbDeviceManager.java#989
     *
     * Android 16 configfs clears only sys.usb.ffs.ready on init.svc.adbd=stopped at lines 14-15;
     * ffs.adb/UDC setup is performed by the separate ready=1 action at lines 20-24:
     * https://android.googlesource.com/platform/system/core/+/4deec4059670028cccb7f9f22bb73813ae71c6f3/rootdir/init.usb.configfs.rc#14
     */
    private fun readUsbState(): UsbRuntimeSnapshot {
        val intent = runCatching {
            context.registerReceiver(null, IntentFilter(ACTION_USB_STATE))
        }.getOrElse { failure ->
            return UsbRuntimeSnapshot(
                state = AdbProbeState.UNAVAILABLE,
                detail = failure.message ?: "USB-state broadcast unavailable.",
            )
        } ?: return UsbRuntimeSnapshot(
            state = AdbProbeState.UNAVAILABLE,
            detail = "No sticky USB-state broadcast was returned.",
        )

        val functions = USB_FUNCTIONS
            .filterTo(linkedSetOf()) { function -> intent.getBooleanExtra(function, false) }
        return UsbRuntimeSnapshot(
            state = AdbProbeState.OBSERVED,
            connected = intent.getBooleanExtra("connected", false),
            configured = intent.getBooleanExtra("configured", false),
            functions = functions,
        )
    }

    private companion object {
        const val ADB_ENABLED = "adb_enabled"
        const val ADB_WIFI_ENABLED = "adb_wifi_enabled"
        const val ACTION_USB_STATE = "android.hardware.usb.action.USB_STATE"
        const val PERSIST_SYS_TEST_HARNESS = "persist.sys.test_harness"
        const val INIT_SVC_ADBD = "init.svc.adbd"
        const val SYS_USB_STATE = "sys.usb.state"
        const val RO_DEBUGGABLE = "ro.debuggable"
        const val SERVICE_ADB_ROOT = "service.adb.root"

        val PROPERTY_NAMES = listOf(
            PERSIST_SYS_TEST_HARNESS,
            INIT_SVC_ADBD,
            SYS_USB_STATE,
            RO_DEBUGGABLE,
            SERVICE_ADB_ROOT,
        )

        val USB_FUNCTIONS = listOf(
            "adb",
            "mtp",
            "ptp",
            "rndis",
            "midi",
            "accessory",
            "audio_source",
            "ncm",
            "uvc",
        )
    }
}
