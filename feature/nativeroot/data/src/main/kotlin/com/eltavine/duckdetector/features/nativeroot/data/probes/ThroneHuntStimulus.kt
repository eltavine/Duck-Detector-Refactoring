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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import android.os.Build
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.binder.PackageManagerPrivateBinderClient
import com.eltavine.duckdetector.features.nativeroot.data.binder.PackageManagerPrivateCallResult

data class ThroneHuntStimulusOutcome(
    val applied: Boolean,
    val detail: String,
)

// Zero-permission packages.list rewrite. The stimulus now bypasses the public
// ApplicationPackageManager path, which forces `new ArrayList<>(mimeTypes)` before Binder.
// 零权限 packages.list 重写。刺激现在绕过公开 ApplicationPackageManager 路径，因为公开客户端
// 会在 Binder 之前强制执行 new ArrayList<>(mimeTypes)。
class ThroneHuntStimulus(
    private val binderClient: PackageManagerPrivateBinderClient = PackageManagerPrivateBinderClient(),
) {

    internal val MARK_A = "duckdetector-throne-a"
    internal val MARK_B = "duckdetector-throne-b"

    /**
     * A value is accepted only when the framework can turn it into an intent filter type.
     * A value must contain `/` with non-empty type/subtype; values without `/` are malformed
     * and ComponentResolver catches the resulting MalformedMimeTypeException.
     * 只有框架能把它变成 intent filter 类型时才视为合法；必须包含 `/` 且类型和子类型非空。
     * 不含 `/` 的值是畸形值，ComponentResolver 会捕获由此产生的 MalformedMimeTypeException。
     */
    internal fun isFrameworkValidMime(value: String): Boolean {
        val slash = value.indexOf('/')
        return slash > 0 && value.length >= slash + 2
    }

    /**
     * Picks a mark that is guaranteed to differ from [current].
     *
     * The next value keeps every framework-valid MIME value, removes either malformed sentinel,
     * and installs the opposite sentinel. That makes the persisted state differ on every call
     * without changing the effective intent-filter set. This is what avoids PACKAGE_CHANGED while
     * still scheduling the settings write.
     * 下一个值会保留所有框架合法 MIME、移除任一畸形哨兵并写入另一个哨兵。这样每次调用
     * 的持久化状态都会变化，但有效 intent-filter 集合不变；这正是避免 PACKAGE_CHANGED 且
     * 仍然调度 settings 写入的原因。
     */
    internal fun nextMark(current: List<String>?): List<String> {
        val currentValues = current.orEmpty()
        val validValues = currentValues.filter(::isFrameworkValidMime)
        val nextSentinel = if (currentValues.contains(MARK_A)) MARK_B else MARK_A
        return validValues + nextSentinel
    }

    private fun <T> failureDetail(result: PackageManagerPrivateCallResult<T>): String {
        return result.detail
    }

    companion object {
        // Must match the android:mimeGroup that this module's manifest declares on the carrier
        // service, otherwise setMimeGroup throws
        // IllegalArgumentException("Unknown MIME group ... for package ...").
        const val MIME_GROUP = "duckdetector-throne-hunt"

        // The reviewed PackageManagerService schedules settings writes with a 10 s delay.
        // Queueing and I/O can extend it, so this observation window is not a completion guarantee
        // or evidence that a manager scan ran. Retain the legacy allowance without attribution.
        const val SETTINGS_WRITE_DELAY_MS = 10_000L
        const val SEARCH_MANAGER_ALLOWANCE_MS = 3_000L
        const val SETTINGS_WRITE_WINDOW_MS = SETTINGS_WRITE_DELAY_MS + SEARCH_MANAGER_ALLOWANCE_MS
    }

    fun apply(context: Context): ThroneHuntStimulusOutcome {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return ThroneHuntStimulusOutcome(
                applied = false,
                detail = "setMimeGroup/getMimeGroup are API 30+; this device reports API " +
                    Build.VERSION.SDK_INT,
            )
        }

        val packageName = context.applicationContext.packageName
        return runCatching {
            val currentResult = binderClient.getMimeGroup(packageName, MIME_GROUP)
            if (!currentResult.isSuccess) {
                return ThroneHuntStimulusOutcome(
                    applied = false,
                    detail = failureDetail(currentResult),
                )
            }
            val current = currentResult.value
            val next = nextMark(current)
            val writeResult = binderClient.setMimeGroup(packageName, MIME_GROUP, next)
            if (!writeResult.isSuccess) {
                return ThroneHuntStimulusOutcome(
                    applied = false,
                    detail = failureDetail(writeResult),
                )
            }

            // A silent no-op is the one failure this probe cannot afford, because it looks exactly
            // like "no KernelSU". Read the group back and refuse to call the round clean otherwise.
            val confirmedResult = binderClient.getMimeGroup(packageName, MIME_GROUP)
            if (!confirmedResult.isSuccess) {
                return ThroneHuntStimulusOutcome(
                    applied = false,
                    detail = failureDetail(confirmedResult),
                )
            }
            val confirmed = confirmedResult.value
            if (confirmed == next) {
                ThroneHuntStimulusOutcome(
                    applied = true,
                    detail = "$MIME_GROUP ${current ?: "(unset)"} -> $next, read back and confirmed",
                )
            } else {
                ThroneHuntStimulusOutcome(
                    applied = false,
                    detail = "$MIME_GROUP read back as $confirmed but expected $next - " +
                        "PackageManagerService short-circuited, packages.list is not being " +
                        "rewritten and this round cannot be trusted",
                )
            }
        }.getOrElse { throwable ->
            ThroneHuntStimulusOutcome(
                applied = false,
                detail = "${PlatformFailureName.of(throwable)}: ${throwable.message}",
            )
        }
    }
}
