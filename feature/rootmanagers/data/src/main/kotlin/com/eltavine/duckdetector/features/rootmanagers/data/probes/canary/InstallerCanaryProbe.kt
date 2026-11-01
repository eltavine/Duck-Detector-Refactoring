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

package com.eltavine.duckdetector.features.rootmanagers.data.probes.canary

import android.Manifest
import android.annotation.TargetApi
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import com.eltavine.duckdetector.core.detector.ConsentDecision
import com.eltavine.duckdetector.core.evidence.FailureName
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryObservation
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryState
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.OverlappingFileLockException
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeoutOrNull

/** Owns the session, callback, staging file, cancellation and local rate limit of one active probe. */
class InstallerCanaryProbe(
    private val context: Context,
    private val callbackTimeoutMillis: Long = 30_000,
) {
    suspend fun observe(): InstallerCanaryObservation {
        return try {
            if (InstallerCanaryConsentStore(context).decision() != ConsentDecision.GRANTED) return InstallerCanaryObservation()
            if (Build.VERSION.SDK_INT !in 33..37) return state(InstallerCanaryState.UNSUPPORTED, "Researched platform range: Android 13–17.")
            try {
                context.assets.open("rootmanagers/installer-canary.apk").close()
            } catch (_: java.io.IOException) {
                return state(InstallerCanaryState.UNAVAILABLE, "A host-signed installer canary asset is not available.")
            }
            if (context.checkSelfPermission(Manifest.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION) != PackageManager.PERMISSION_GRANTED) {
                return state(InstallerCanaryState.UNAVAILABLE, "The host does not hold UPDATE_PACKAGES_WITHOUT_USER_ACTION.")
            }
            if (!context.packageManager.canRequestPackageInstalls()) {
                return state(InstallerCanaryState.USER_ACTION_REQUIRED, "Source-install authorization is unavailable; no settings screen was opened.")
            }
            FileOutputStream(File(context.filesDir, "installer-canary.lock"), true).channel.use { channel ->
                val lock = try { channel.tryLock() } catch (_: OverlappingFileLockException) { null }
                if (lock == null) return state(InstallerCanaryState.THROTTLED, "Another probe owns the installer session.")
                lock.use {
                    val prefs = context.getSharedPreferences("installer_permission_canary", Context.MODE_PRIVATE)
                    val now = SystemClock.elapsedRealtime()
                    val last = prefs.getLong("last_attempt_elapsed", -60_001)
                    if (now - last in 0..60_000) return state(InstallerCanaryState.THROTTLED, "Wait at least 60 seconds between installation checks.")
                    val file = File.createTempFile("installer-canary-", ".apk", context.cacheDir)
                    try {
                        context.assets.open("rootmanagers/installer-canary.apk").use { input ->
                            file.outputStream().use { input.copyTo(it) }
                        }
                        val archive = InstallerCanaryArchive(context)
                        archive.validate(file)
                        currentCoroutineContext().ensureActive()
                        check(prefs.edit().putLong("last_attempt_elapsed", now).commit())
                        val observation = commit(file, archive.missingGroup)
                        if (observation.state == InstallerCanaryState.UNEXPECTED_SUCCESS) {
                            InstallerCanaryConsentStore(context).decide(false)
                        }
                        observation.withDirectoryObservations()
                    } finally {
                        file.delete()
                    }
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            state(InstallerCanaryState.UNAVAILABLE, FailureName.messageOrName(failure))
        }
    }

    @TargetApi(33)
    private suspend fun commit(file: File, missingGroup: String): InstallerCanaryObservation {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
            setSize(file.length())
        }
        val sessionId = installer.createSession(params)
        val action = "${context.packageName}.INSTALLER_CANARY.${UUID.randomUUID()}"
        val result = CompletableDeferred<InstallerCanaryObservation>()
        var registered = false
        var pending: PendingIntent? = null
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != action || intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1) != sessionId) return
                val legacyKey = "android.content.pm.extra.LEGACY_STATUS"
                result.complete(InstallerCanaryResultPolicy.interpret(
                    context.packageName, missingGroup,
                    intent.getIntExtra(PackageInstaller.EXTRA_STATUS, Int.MIN_VALUE),
                    if (intent.hasExtra(legacyKey)) intent.getIntExtra(legacyKey, Int.MIN_VALUE) else null,
                    intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE),
                ))
            }
        }
        try {
            context.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
            registered = true
            pending = PendingIntent.getBroadcast(context, sessionId,
                Intent(action).setPackage(context.packageName), PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_ONE_SHOT)
            installer.openSession(sessionId).use { session ->
                session.openWrite("base.apk", 0, file.length()).use { output ->
                    file.inputStream().use { it.copyTo(output) }
                    session.fsync(output)
                }
                currentCoroutineContext().ensureActive()
                session.commit(pending.intentSender)
            }
            return withTimeoutOrNull(callbackTimeoutMillis) { result.await() }
                ?: state(InstallerCanaryState.TIMED_OUT, "Installer callback timed out.")
        } finally {
            // Only abandon this probe's own session, including pending-user-action sessions.
            runCatching { installer.abandonSession(sessionId) }
            pending?.cancel()
            if (registered) context.unregisterReceiver(receiver)
        }
    }

    private fun state(state: InstallerCanaryState, detail: String) = InstallerCanaryObservation(state, detail = detail)
}
