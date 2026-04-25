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

import android.annotation.SuppressLint
import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.app.Notification
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.eltavine.duckdetector.MainActivity
import com.eltavine.duckdetector.R

class ScanProgressNotifier(
    private val context: Context,
    private val formatter: ScanProgressNotificationFormatter = ScanProgressNotificationFormatter(),
) {

    fun update(
        permissionState: ScanNotificationPermissionState,
        snapshot: ScanProgressNotificationSnapshot,
    ) {
        if (!permissionState.notificationsGranted) {
            cancel()
            return
        }
        createChannelIfNeeded()
        val formatted = formatter.format(snapshot)
        if (snapshot.scanning) {
            NotificationManagerCompat.from(context).cancel(COMPLETION_NOTIFICATION_ID)
            postScanningNotification(permissionState, snapshot, formatted)
        } else {
            NotificationManagerCompat.from(context).cancel(SCAN_NOTIFICATION_ID)
            postCompletionNotification(formatted)
        }
    }

    fun cancel() {
        runCatching {
            NotificationManagerCompat.from(context).cancel(SCAN_NOTIFICATION_ID)
            NotificationManagerCompat.from(context).cancel(COMPLETION_NOTIFICATION_ID)
        }
    }

    private fun postScanningNotification(
        permissionState: ScanNotificationPermissionState,
        snapshot: ScanProgressNotificationSnapshot,
        formatted: ScanProgressNotificationModel,
    ) {
        if (!hasNotificationPermission()) {
            return
        }
        val builder = baseBuilder(formatted)
            .setCategory(NotificationCompat.CATEGORY_PROGRESS)
            .setOngoing(true)
            .setAutoCancel(false)

        if (permissionState.liveUpdatesSupported && permissionState.liveUpdatesGranted) {
            builder
                .setRequestPromotedOngoing(true)
                .setShortCriticalText(formatted.shortCriticalText)
                .setStyle(
                    NotificationCompat.ProgressStyle()
                        .setProgress(formatted.progressPercent),
                )
        } else {
            builder.setProgress(
                snapshot.totalDetectorCount.coerceAtLeast(1),
                snapshot.readyDetectorCount.coerceIn(
                    0,
                    snapshot.totalDetectorCount.coerceAtLeast(1),
                ),
                false,
            )
        }

        runCatching {
            notifySafely(SCAN_NOTIFICATION_ID, builder.build())
        }.onFailure { throwable ->
            if (throwable is SecurityException) {
                return@onFailure
            }
            cancel()
        }
    }

    private fun postCompletionNotification(
        formatted: ScanProgressNotificationModel,
    ) {
        if (!hasNotificationPermission()) {
            return
        }
        val builder = baseBuilder(formatted)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setOngoing(false)
            .setAutoCancel(true)
            .setTimeoutAfter(FINISHED_TIMEOUT_MS)
            .setStyle(NotificationCompat.BigTextStyle().bigText(formatted.text))

        runCatching {
            notifySafely(COMPLETION_NOTIFICATION_ID, builder.build())
        }.onFailure { throwable ->
            if (throwable is SecurityException) {
                return@onFailure
            }
            cancel()
        }
    }

    @SuppressLint("MissingPermission")
    private fun notifySafely(
        notificationId: Int,
        notification: Notification,
    ) {
        NotificationManagerCompat.from(context).notify(notificationId, notification)
    }

    private fun baseBuilder(
        formatted: ScanProgressNotificationModel,
    ): NotificationCompat.Builder {
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification_small)
            .setContentTitle(formatted.title)
            .setContentText(formatted.text)
            .setSubText(formatted.subText)
            .setContentIntent(contentIntent())
            .setOnlyAlertOnce(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setLocalOnly(true)
    }

    private fun createChannelIfNeeded() {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) {
            return
        }
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Scan progress",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Overall Duck Detector scan progress and final dashboard verdict."
                setShowBadge(false)
            },
        )
    }

    private fun contentIntent(): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun hasNotificationPermission(): Boolean {
        if (Build.VERSION.SDK_INT < 33) {
            return true
        }
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
    }

    companion object {
        private const val CHANNEL_ID = "scan_progress"
        private const val SCAN_NOTIFICATION_ID = 4107
        private const val COMPLETION_NOTIFICATION_ID = 4108
        private const val FINISHED_TIMEOUT_MS = 20_000L
    }
}
