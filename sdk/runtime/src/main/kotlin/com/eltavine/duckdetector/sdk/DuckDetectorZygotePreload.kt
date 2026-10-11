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

package com.eltavine.duckdetector.sdk

import android.app.ZygotePreload
import android.content.pm.ApplicationInfo
import android.util.Log
import android.system.Os
import com.eltavine.duckdetector.capability.selinuxpolicy.data.SelinuxContextValidityPreload

/**
 * The detection work that has to run in the app zygote, before any isolated process forks from it.
 *
 * The SDK's manifest names this class in `android:zygotePreloadName`, so a host gets it without
 * declaring anything; a host with its own [ZygotePreload] delegates to it. It runs every
 * detector's app zygote preload in catalog order and then captures the SELinux context validity
 * evidence that the SELinux and LSPosed detectors read from their app zygote carriers. Without it,
 * both carriers report their app zygote evidence as unavailable.
 */
public class DuckDetectorZygotePreload : ZygotePreload {
    override fun doPreload(appInfo: ApplicationInfo) {
        trace("preload entry pid=${Os.getpid()} uid=${Os.getuid()} appUid=${appInfo.uid} " +
            "package=${appInfo.packageName} process=${appInfo.processName} apk=${appInfo.sourceDir}")
        val selinuxContextValidity = SelinuxContextValidityPreload()
        trace("SELinux preload collector constructed")
        selinuxContextValidity.preload(appInfo, trace = ::trace) {
            DetectorCatalog.all.forEach { detector ->
                trace("detector: ${detector.id}")
                detector.appZygotePreload(appInfo)
            }
        }
        trace("preload finished")
    }

    // An app zygote killed with SIGKILL leaves no crash report, so the last step logged before it
    // died is the only record of what the preload was doing.
    private fun trace(step: String) {
        Log.i(TRACE_TAG, step)
    }

    private companion object {
        const val TRACE_TAG = "DuckZygotePreload"
    }
}
