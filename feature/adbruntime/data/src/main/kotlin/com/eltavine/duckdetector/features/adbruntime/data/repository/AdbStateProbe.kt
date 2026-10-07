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
     * AdbService cannot synchronise the ADB Settings while DISALLOW_DEBUGGING_FEATURES is active, so
     * a restricted user's Settings may be stale (EVIDENCE.md, "Settings and lifecycle context").
     */
    private fun readDebuggingRestriction(): Boolean? = runCatching {
        context.getSystemService(UserManager::class.java)
            .hasUserRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES)
    }.getOrNull()

    private fun readProperties(): AdbPropertySnapshot {
        val nativeSnapshot = propertyReads.collectNativeSnapshot(PROPERTY_NAMES)
        val cache = linkedMapOf<String, MultiSourcePropertyRead>()

        fun read(name: String): String? =
            propertyReads.readProperty(
                property = name,
                category = SystemPropertyCategory.SECURITY_CORE,
                cache = cache,
                nativeSnapshot = nativeSnapshot,
            ).preferredValue.trim().ifBlank { null }

        return AdbPropertySnapshot(
            testHarnessMode = read(PERSIST_SYS_TEST_HARNESS),
            initAdbdState = read(INIT_SVC_ADBD),
            sysUsbState = read(SYS_USB_STATE),
            serviceAdbRoot = read(SERVICE_ADB_ROOT),
            roDebuggable = read(RO_DEBUGGABLE),
        )
    }

    /**
     * ACTION_USB_STATE is UsbDeviceManager's sticky snapshot of the applied gadget functions, not a
     * probe of adbd: configfs can clear sys.usb.ffs.ready when adbd stops without tearing the gadget
     * down in the same trigger, so even a configured adb gadget stays context (EVIDENCE.md,
     * "USB runtime broadcast").
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
        const val SERVICE_ADB_ROOT = "service.adb.root"
        const val RO_DEBUGGABLE = "ro.debuggable"

        val PROPERTY_NAMES = listOf(
            PERSIST_SYS_TEST_HARNESS,
            INIT_SVC_ADBD,
            SYS_USB_STATE,
            SERVICE_ADB_ROOT,
            RO_DEBUGGABLE,
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
