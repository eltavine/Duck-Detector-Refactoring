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

package com.eltavine.duckdetector.features.selinux.data.probes

import java.util.concurrent.TimeUnit

data class SelinuxAuditLogcatReadResult(
    val checked: Boolean,
    val output: String,
    val failureReason: String?,
)

open class SelinuxAuditLogcatReader {

    open fun readRecentAuditLogs(): SelinuxAuditLogcatReadResult {
        var process: Process? = null
        return try {
            process = ProcessBuilder(
                "logcat",
                "-d",
                "-b",
                "events",
                "-v",
                "brief",
                "-s",
                "auditd:I",
                "*:S",
                "-t",
                AUDIT_LOGCAT_LINE_COUNT.toString(),
            )
                .redirectErrorStream(true)
                .start()

            val output = process.inputStream.bufferedReader().use { it.readText().trim() }
            val completed = process.waitFor(PROCESS_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                return SelinuxAuditLogcatReadResult(
                    checked = false,
                    output = "",
                    failureReason = "Recent auditd event logs timed out.",
                )
            }

            if (output.isLogAccessDenied()) {
                return SelinuxAuditLogcatReadResult(
                    checked = false,
                    output = output,
                    failureReason = "Recent auditd event logs are not readable from the current app context.",
                )
            }

            SelinuxAuditLogcatReadResult(
                checked = true,
                output = output,
                failureReason = null,
            )
        } catch (throwable: Throwable) {
            SelinuxAuditLogcatReadResult(
                checked = false,
                output = "",
                failureReason = if (throwable.message.isLogAccessDenied()) {
                    "Recent auditd event logs are not readable from the current app context."
                } else {
                    throwable.message ?: "logcat probe failed"
                },
            )
        } finally {
            process?.destroy()
        }
    }

    private fun String?.isPermissionDenied(): Boolean {
        return this?.contains("Permission denied", ignoreCase = true) == true ||
                this?.contains("EACCES", ignoreCase = true) == true
    }

    private fun String?.isLogAccessDenied(): Boolean {
        return isPermissionDenied() ||
                this?.contains("not allowed to read logs", ignoreCase = true) == true ||
                this?.contains("READ_LOGS", ignoreCase = true) == true
    }

    private companion object {
        private const val PROCESS_TIMEOUT_SECONDS = 5L
        private const val AUDIT_LOGCAT_LINE_COUNT = 120
    }
}
