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

package com.eltavine.duckdetector

import android.content.pm.PackageInstaller
import android.os.Handler
import android.os.Looper
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.features.rootmanagers.data.probes.canary.InstallerCanaryConsentStore
import com.eltavine.duckdetector.features.rootmanagers.data.probes.canary.InstallerCanaryProbe
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

/** Run only on disposable test devices; see the feature's research verification instructions. */
class InstallerCanaryRuntimeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun disabledProbeCreatesNoSession() = runBlocking {
        InstallerCanaryConsentStore(context).decide(false)
        val before = context.packageManager.packageInstaller.mySessions.map { it.sessionId }
        assertEquals(InstallerCanaryState.DISABLED, InstallerCanaryProbe(context).observe().state)
        assertEquals(before, context.packageManager.packageInstaller.mySessions.map { it.sessionId })
    }

    @Test fun installationResultPreservesHostAndCleansSession() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        val expected = requireNotNull(args.getString("canaryExpected")) { "Supply canaryExpected=absent, restricted, or the fixture owner package" }
        val pm = context.packageManager
        @Suppress("DEPRECATION") val before = pm.getPackageInfo(context.packageName, 0)
        val sessions = pm.packageInstaller.mySessions.map { it.sessionId }.toSet()
        val prefs = context.getSharedPreferences("installer_permission_canary", 0)
        prefs.edit().remove("last_attempt_elapsed").commit()
        InstallerCanaryConsentStore(context).decide(true)
        try {
            val result = InstallerCanaryProbe(context).observe()
            when (expected) {
                "absent" -> assertEquals(result.toString(), InstallerCanaryState.PERMISSION_NOT_OBSERVED, result.state)
                "unsupported" -> assertEquals(result.toString(), InstallerCanaryState.UNSUPPORTED, result.state)
                "restricted" -> assertEquals(result.toString(), InstallerCanaryState.USER_ACTION_REQUIRED, result.state)
                else -> {
                    assertEquals(result.toString(), InstallerCanaryState.PERMISSION_OWNER_OBSERVED, result.state)
                    assertEquals(expected, result.ownerPackageName)
                }
            }
            if (expected != "restricted" && expected != "unsupported") {
                assertEquals(InstallerCanaryState.THROTTLED, InstallerCanaryProbe(context).observe().state)
                prefs.edit().remove("last_attempt_elapsed").commit()
                assertEquals(InstallerCanaryState.TIMED_OUT,
                    InstallerCanaryProbe(context, callbackTimeoutMillis = 0).observe().state)
            }
            // Abandonment is queued by system_server; wait for observable cleanup, not a fixed sleep.
            withTimeout(5_000) {
                while (pm.packageInstaller.mySessions.any { it.sessionId !in sessions }) delay(25)
            }
            @Suppress("DEPRECATION") val after = pm.getPackageInfo(context.packageName, 0)
            assertEquals(before.longVersionCode, after.longVersionCode)
            assertEquals(before.applicationInfo!!.sourceDir, after.applicationInfo!!.sourceDir)
            assertEquals(before.applicationInfo!!.uid, after.applicationInfo!!.uid)
            assertNotNull(pm.getLaunchIntentForPackage(context.packageName))
            assertTrue(pm.packageInstaller.mySessions.all { it.sessionId in sessions })
            assertTrue(context.cacheDir.listFiles().orEmpty().none { it.name.startsWith("installer-canary-") })
        } finally {
            InstallerCanaryConsentStore(context).decide(false)
        }
    }

    @Test fun cancellationAbandonsOwnedSession() = runBlocking {
        val installer = context.packageManager.packageInstaller
        val previous = installer.mySessions.map { it.sessionId }.toSet()
        val created = CompletableDeferred<Unit>()
        val prefs = context.getSharedPreferences("installer_permission_canary", 0)
        prefs.edit().remove("last_attempt_elapsed").commit()
        InstallerCanaryConsentStore(context).decide(true)
        val task = async(Dispatchers.IO, start = CoroutineStart.LAZY) { InstallerCanaryProbe(context).observe() }
        val callback = object : PackageInstaller.SessionCallback() {
            override fun onCreated(sessionId: Int) {
                if (installer.getSessionInfo(sessionId)?.installerPackageName == context.packageName) {
                    created.complete(Unit)
                    task.cancel()
                }
            }
            override fun onBadgingChanged(sessionId: Int) = Unit
            override fun onActiveChanged(sessionId: Int, active: Boolean) = Unit
            override fun onProgressChanged(sessionId: Int, progress: Float) = Unit
            override fun onFinished(sessionId: Int, success: Boolean) = Unit
        }
        installer.registerSessionCallback(callback, Handler(Looper.getMainLooper()))
        try {
            task.start()
            withTimeout(5_000) { created.await() }
            task.join()
            assertTrue("Cancellation must reach the active probe", task.isCancelled)
            withTimeout(5_000) {
                while (installer.mySessions.any { it.sessionId !in previous }) delay(25)
            }
            assertTrue(context.cacheDir.listFiles().orEmpty().none { it.name.startsWith("installer-canary-") })
        } finally {
            task.cancelAndJoin()
            installer.unregisterSessionCallback(callback)
            InstallerCanaryConsentStore(context).decide(false)
        }
    }

}
