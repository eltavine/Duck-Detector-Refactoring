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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Process
import android.os.UserHandle
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCallOutcome
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationTargetException
import java.util.UUID
import kotlin.coroutines.cancellation.CancellationException

internal class HmaPlatformCalls(private val context: Context) {
    private val componentName = "${context.packageName}.AbsentHmaReceiver_${UUID.randomUUID().toString().replace("-", "")}"
    private val action = "${context.packageName}.HMA_PROBE.${UUID.randomUUID()}"

    fun intent(packageName: String): Intent = Intent(action).apply {
        component = ComponentName(packageName, componentName)
        addFlags(Intent.FLAG_RECEIVER_FOREGROUND)
    }

    @Suppress("DEPRECATION")
    fun packageInfo(packageName: String): HmaCallOutcome = observe {
        context.packageManager.getPackageInfo(packageName, MATCH_ANY_USER)
    }

    @Suppress("DEPRECATION")
    fun applicationInfo(packageName: String): HmaCallOutcome = observe {
        context.packageManager.getApplicationInfo(packageName, MATCH_ANY_USER)
    }

    fun crossUserBroadcast(packageName: String): HmaCallOutcome = observe {
        val ownUser = Process.myUid() / PER_USER_RANGE
        val otherUser = if (ownUser == 0) 1 else 0
        // ContextImpl supplies the real IApplicationThread. No global hidden-API exemption is added.
        HiddenApiBypass.invoke(Context::class.java, context, "sendBroadcastAsUser",
            intent(packageName), UserHandle.getUserHandleForUid(otherUser * PER_USER_RANGE))
    }

    private fun observe(call: () -> Any?): HmaCallOutcome = try {
        call()
        HmaCallOutcome.RETURNED
    } catch (failure: Exception) {
        val cause = if (failure is InvocationTargetException) failure.targetException else failure
        if (cause is CancellationException) throw cause
        when (cause) {
            is SecurityException -> HmaCallOutcome.SECURITY_EXCEPTION
            is PackageManager.NameNotFoundException -> HmaCallOutcome.NAME_NOT_FOUND
            is ReflectiveOperationException -> HmaCallOutcome.UNAVAILABLE
            is LinkageError -> HmaCallOutcome.UNAVAILABLE
            else -> HmaCallOutcome.FAILED
        }
    } catch (_: LinkageError) {
        HmaCallOutcome.UNAVAILABLE
    }

    companion object {
        // PackageManager.MATCH_ANY_USER is @hide; AOSP 10/14/16 require cross-user permission
        // even for a query of the caller's own user. The public wrapper may convert null to NNFE.
        private const val MATCH_ANY_USER = 0x00400000
        const val PER_USER_RANGE = 100000
    }
}
