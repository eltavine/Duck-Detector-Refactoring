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

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import android.os.Process
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidPermissionEvidence
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidPermissionObservation
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidPermissionPolicy
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

internal data class HmaUidPermissionCaller(
    val uid: Int,
    val packageName: String,
    val sdk: Int,
    val internetGranted: Boolean,
    val nonInstantDefinitions: Boolean,
)

internal class HmaUidPermissionProbe(
    private val calls: HmaUidPackageCalls,
    private val caller: () -> HmaUidPermissionCaller,
    private val now: () -> Long = System::nanoTime,
    private val budgetNanos: Long = 1_000_000_000L,
    private val candidateLimit: Int = 16,
) {
    constructor(context: Context, calls: HmaUidPackageCalls) : this(calls, {
        HmaUidPermissionCaller(
            Process.myUid(), context.packageName, Build.VERSION.SDK_INT,
            context.packageManager.checkPermission(INTERNET, context.packageName) == PackageManager.PERMISSION_GRANTED,
            HmaUidPermissionPolicy.PERMISSIONS.all {
                context.packageManager.getPermissionInfo(it, 0).protectionFlags and
                    PermissionInfo.PROTECTION_FLAG_INSTANT == 0
            },
        )
    })

    suspend fun run(visibility: DangerousPackageVisibility): HmaBehaviorCheck {
        coroutineContext.ensureActive()
        val kind = HmaCheckKind.UID_PERMISSION_VISIBILITY
        if (visibility != DangerousPackageVisibility.FULL) return HmaBehaviorCheck(
            kind, HmaCheckState.PERMISSION_LIMITED, "Full package visibility is required for the experimental UID permission comparison.")
        val identity = try {
            caller()
        } catch (failure: Exception) {
            return failed(failure)
        } catch (failure: LinkageError) {
            return failed(failure)
        }
        if (identity.sdk !in 35..37 || identity.uid % 100000 !in 10000..19999 || !identity.nonInstantDefinitions) {
            return HmaBehaviorCheck(kind, HmaCheckState.UNSUPPORTED,
                "Requires reviewed Android 15–17 permission semantics, an ordinary caller UID and non-instant permission definitions.")
        }
        val firstUid = identity.uid / 100000 * 100000 + 10000
        var checked = 0
        var unstable = 0
        var candidates = 0
        var limited = false
        var before = false
        var after = false
        var failure: HmaUidCallFailure? = null
        val evidence = mutableListOf<HmaUidPermissionEvidence>()
        val started = now()
        try {
            before = controls(identity)
            if (before) for (uid in firstUid until firstUid + 10000) {
                coroutineContext.ensureActive()
                if (now() - started >= budgetNanos) break
                val granted = HmaUidPermissionPolicy.PERMISSIONS.filter { calls.permission(uid, it) }
                if (granted.isEmpty() || calls.packages(uid).isNotEmpty()) {
                    checked++
                    continue
                }
                candidates++
                if (candidates > candidateLimit) { limited = true; break }
                // Both passes use the Binder proxy; a cached empty array is not a repeat.
                val repeated = granted.filter { calls.permission(uid, it) }
                val absentAgain = calls.packages(uid).isEmpty()
                checked++
                if (repeated.isNotEmpty() && absentAgain) evidence += HmaUidPermissionEvidence(uid, repeated)
                else unstable++
            }
        } catch (cause: Exception) {
            failure = HmaUidCallFailure.from(cause)
        } catch (cause: LinkageError) {
            failure = HmaUidCallFailure.from(cause)
        }
        // Failed final controls invalidate every foreign UID, including already collected hits.
        coroutineContext.ensureActive()
        try {
            after = controls(identity)
        } catch (cause: Exception) {
            failure = HmaUidCallFailure.from(cause)
        } catch (cause: LinkageError) {
            failure = HmaUidCallFailure.from(cause)
        }
        return HmaUidPermissionPolicy.evaluate(HmaUidPermissionObservation(
            firstUid, checked, before && after, evidence, unstable, limited, failure?.state, failure?.detail.orEmpty(),
        ))
    }

    private fun controls(caller: HmaUidPermissionCaller): Boolean =
        caller.packageName in calls.packages(caller.uid) &&
            calls.permission(caller.uid, INTERNET) == caller.internetGranted &&
            !calls.permission(caller.uid, "")

    private fun failed(cause: Throwable): HmaBehaviorCheck {
        val failure = HmaUidCallFailure.from(cause)
        return HmaBehaviorCheck(HmaCheckKind.UID_PERMISSION_VISIBILITY, failure.state,
            "Experimental UID permission comparison unavailable: ${failure.detail}")
    }

    private companion object { const val INTERNET = "android.permission.INTERNET" }
}
