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

package com.eltavine.duckdetector.core.notifications

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat

data class ScanNotificationPermissionState(
    val notificationsGranted: Boolean,
    val liveUpdatesSupported: Boolean,
    val liveUpdatesGranted: Boolean,
)

object ScanNotificationPermissions {

    fun read(context: Context): ScanNotificationPermissionState {
        val notificationsGranted = hasNotificationPermission(context)
        val liveUpdatesSupported = Build.VERSION.SDK_INT >= 36
        val liveUpdatesGranted = if (liveUpdatesSupported) {
            context.getSystemService(NotificationManager::class.java)
                ?.canPostPromotedNotifications() == true
        } else {
            false
        }
        return ScanNotificationPermissionState(
            notificationsGranted = notificationsGranted,
            liveUpdatesSupported = liveUpdatesSupported,
            liveUpdatesGranted = liveUpdatesGranted,
        )
    }

    fun hasNotificationPermission(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 33) {
            return true
        }
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
    }

    fun appNotificationSettingsIntent(context: Context): Intent {
        return Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        }
    }

    fun appNotificationPromotionSettingsIntent(context: Context): Intent {
        return Intent(Settings.ACTION_APP_NOTIFICATION_PROMOTION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
        }
    }
}
