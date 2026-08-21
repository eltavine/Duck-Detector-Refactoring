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

package com.eltavine.duckdetector.features.mount.data.zygotenext

import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Manifest component identity for the API 37 native service.
 *
 * Android 17 routes this component to zygote_next and loads libmain.so instead of creating this
 * Java class. The manager never binds it on older releases, where nativeService is unavailable.
 */
class ZygoteNextProbeService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null
}
