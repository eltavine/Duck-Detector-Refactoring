/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector

import android.app.Application
import android.util.Log
import com.eltavine.duckdetector.features.crashreport.data.CrashHandler

class DuckDetectorApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Mark launch started BEFORE installing crash handler,
        // so startup crashes are detectable on next launch
        CrashHandler.markLaunchStarted(this)

        installCrashHandler()
    }

    private fun installCrashHandler() {
        if (BuildConfig.DEBUG) {
            Log.d("DuckDetectorApp", "Installing crash handler")
        }
        // CrashHandler.install is idempotent — if CrashInitProvider already
        // installed it, this call is a no-op.
        CrashHandler.install(this)
    }
}
