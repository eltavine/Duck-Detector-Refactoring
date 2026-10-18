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
import android.os.Build
import com.eltavine.duckdetector.features.dangerousapps.domain.DangerousPackageVisibility
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorCheck
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaBehaviorPolicy
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckKind
import com.eltavine.duckdetector.features.dangerousapps.domain.HmaCheckState

class HmaBehaviorProbe(context: Context) {
    private val context = context.applicationContext

    suspend fun run(
        packages: List<String>,
        visibility: DangerousPackageVisibility,
        corroboratedPackages: Set<String> = emptySet(),
    ): List<HmaBehaviorCheck> {
        // Hidden flag and final-receiver semantics were checked against AOSP 10, 14, 16 and 17.
        if (Build.VERSION.SDK_INT !in 29..37) return HmaCheckKind.entries.map {
            HmaBehaviorCheck(it, HmaCheckState.UNSUPPORTED, "Platform semantics have not been verified for API ${Build.VERSION.SDK_INT}.")
        }
        val ordered = HmaBehaviorPolicy.targetOrder(packages, corroboratedPackages)
        val selected = ordered.take(MAX_EXCEPTION_TARGETS)
        val platform = HmaPlatformCalls(context)
        val exceptions = HmaExceptionProbe()
        val exceptionResults = listOf(
            exceptions.run(HmaCheckKind.BROADCAST_CROSS_USER, context.packageName, selected, platform::crossUserBroadcast),
            exceptions.run(HmaCheckKind.PACKAGE_INFO_EXCEPTION, context.packageName, selected, platform::packageInfo),
            exceptions.run(HmaCheckKind.APPLICATION_INFO_EXCEPTION, context.packageName, selected, platform::applicationInfo),
        )
        // Permission anomalies prioritize the callback budget without being counted as independent evidence.
        val callbackTargets = HmaBehaviorPolicy.targetOrder(ordered,
            corroboratedPackages + exceptionResults.flatMap { it.packages }).take(MAX_CALLBACK_TARGETS)
        val results = exceptionResults + HmaBroadcastResultProbe(context, platform).run(callbackTargets) +
            HmaUidVisibilityProbe(context).run(visibility) + HmaSeccompUidProbe().run()
        return results.map { result ->
            val evaluated = when (result.kind) {
                HmaCheckKind.BROADCAST_RESULT_TO, HmaCheckKind.BROADCAST_RESULT_COMPLETION -> callbackTargets.size
                else -> selected.size
            }
            if (result.kind == HmaCheckKind.UID_TASK_VISIBILITY ||
                result.kind == HmaCheckKind.SECCOMP_UID_FILTER) result else result.copy(
                state = if (ordered.size > evaluated && result.state == HmaCheckState.CONSISTENT)
                    HmaCheckState.PARTIAL else result.state,
                detail = "${result.detail} Target scope: $evaluated/${ordered.size}; API ${Build.VERSION.SDK_INT}.",
            )
        }
    }

    private companion object {
        const val MAX_EXCEPTION_TARGETS = 128
        const val MAX_CALLBACK_TARGETS = 128
    }
}
