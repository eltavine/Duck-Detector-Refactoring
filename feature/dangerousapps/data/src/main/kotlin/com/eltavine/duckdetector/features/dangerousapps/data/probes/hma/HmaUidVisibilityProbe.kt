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
import android.os.Process
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidVisibilityObservation
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaUidVisibilityPolicy
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

internal class HmaUidVisibilityProbe(
    private val context: Context,
    private val bridge: HmaUidTaskBridge = HmaUidTaskBridge(),
) {
    suspend fun run(visibility: DangerousPackageVisibility): HmaBehaviorCheck {
        val kind = HmaCheckKind.UID_TASK_VISIBILITY
        if (visibility != DangerousPackageVisibility.FULL) {
            return HmaBehaviorCheck(kind, HmaCheckState.PERMISSION_LIMITED,
                "Full package visibility is required to compare UID tasks with package associations.")
        }
        val self = Process.myUid()
        val base = self / HmaPlatformCalls.PER_USER_RANGE * HmaPlatformCalls.PER_USER_RANGE
        if (self - base !in 10000..19999) {
            return HmaBehaviorCheck(kind, HmaCheckState.UNSUPPORTED, "Caller is outside the ordinary application UID range.")
        }
        val snapshot = bridge.scan(base + 10000, base + 19999)
        if (snapshot.status !in setOf(HmaUidTaskBridge.COMPLETE, HmaUidTaskBridge.PARTIAL)) {
            return HmaBehaviorCheck(kind, when (snapshot.status) {
                HmaUidTaskBridge.RESTRICTED -> HmaCheckState.PERMISSION_LIMITED
                HmaUidTaskBridge.TIMEOUT -> HmaCheckState.INCONCLUSIVE
                else -> HmaCheckState.UNAVAILABLE
            }, "Native child status=${snapshot.status}, errno/signal=${snapshot.error}. ${snapshot.failure}")
        }
        val pm = context.packageManager
        val unassociated = mutableListOf<Int>()
        var associationFailure = false
        // Verify the association service before and after comparing foreign UIDs.
        val before = runCatching { context.packageName in pm.getPackagesForUid(self).orEmpty() }.getOrDefault(false)
        var candidates = 0
        if (before) for (uid in snapshot.tasks.keys) {
            coroutineContext.ensureActive()
            val packages = runCatching { pm.getPackagesForUid(uid) }
            if (packages.isFailure) { associationFailure = true; continue }
            if (!packages.getOrNull().isNullOrEmpty()) continue
            candidates++
            if (candidates > MAX_RECHECKS) break
            val repeated = bridge.scan(uid, uid)
            if (repeated.status != HmaUidTaskBridge.COMPLETE) associationFailure = true
            val stillUnassociated = runCatching { pm.getPackagesForUid(uid).isNullOrEmpty() }
            if (stillUnassociated.isFailure) associationFailure = true
            if (repeated.status == HmaUidTaskBridge.COMPLETE && uid in repeated.tasks &&
                stillUnassociated.getOrNull() == true) unassociated += uid
        }
        val after = runCatching { context.packageName in pm.getPackagesForUid(self).orEmpty() }.getOrDefault(false)
        return HmaUidVisibilityPolicy.evaluate(HmaUidVisibilityObservation(
            complete = snapshot.status == HmaUidTaskBridge.COMPLETE,
            checked = snapshot.checked,
            firstUid = base + 10000,
            taskUids = snapshot.tasks.keys,
            callerUid = self,
            callerAssociationBefore = before,
            callerAssociationAfter = after,
            unassociated = unassociated,
            verificationFailed = associationFailure,
            verificationLimitReached = candidates > MAX_RECHECKS,
        ))
    }

    private companion object { const val MAX_RECHECKS = 16 }
}
