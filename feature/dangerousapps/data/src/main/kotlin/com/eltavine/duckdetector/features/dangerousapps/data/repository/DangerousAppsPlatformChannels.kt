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

package com.eltavine.duckdetector.features.dangerousapps.data.repository

import android.content.ComponentName
import android.content.Intent
import android.provider.Settings
import android.text.TextUtils
import java.io.File
import kotlin.random.Random

internal fun DangerousAppsRepository.isAccessibilityServiceEnabled(packageName: String): Boolean {
    return try {
        val enabledServices = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false

        val services = TextUtils.SimpleStringSplitter(':').apply {
            setString(enabledServices)
        }

        services.any { service -> service.startsWith("$packageName/") }
    } catch (_: Exception) {
        false
    }
}

internal fun DangerousAppsRepository.detectSceneBroadcast(): Boolean {
    val token = Random.nextLong().toULong().toString(16) +
        Random.nextLong().toULong().toString(16)
    val pocPath = "/sdcard/$token"
    val detected = try {
        val intent = Intent().apply {
            component = ComponentName(
                "com.omarea.vtools",
                "com.omarea.scene_mode.ReceiverShortcut",
            )
            putExtra("packageName", "x; touch $pocPath; id >> $pocPath; #")
        }
        context.sendBroadcast(intent)
        waitForScenePocFile(pocPath)
    } catch (_: Exception) {
        false
    } finally {
        runCatching { File(pocPath).delete() }
    }
    return detected
}
