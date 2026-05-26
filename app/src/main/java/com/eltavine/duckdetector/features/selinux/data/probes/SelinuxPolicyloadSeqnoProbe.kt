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

import java.io.FileInputStream
import java.io.IOException
import java.io.RandomAccessFile

enum class SelinuxPolicyloadSeqnoState {
    CLEAN,
    SUSPICIOUS,
    INCONCLUSIVE,
    UNAVAILABLE,
}

data class SelinuxPolicyloadSeqnoResult(
    val state: SelinuxPolicyloadSeqnoState,
    val available: Boolean,
    val probeAttempted: Boolean,
    val statusSequence: Long? = null,
    val statusPolicyload: Long? = null,
    val accessSeqno: Long? = null,
    val processClass: Int? = null,
    val failureReason: String? = null,
    val notes: List<String> = emptyList(),
)

class SelinuxPolicyloadSeqnoProbe {

    fun inspect(): SelinuxPolicyloadSeqnoResult {
        return runCatching {
            val status = readStatusStable()
            val access = queryAccessDecision()
            interpret(status, access)
        }.getOrElse { throwable ->
            SelinuxPolicyloadSeqnoResult(
                state = SelinuxPolicyloadSeqnoState.UNAVAILABLE,
                available = false,
                probeAttempted = true,
                failureReason = throwable.message ?: throwable.javaClass.simpleName,
                notes = listOf(ZYGOTE_PRELOAD_NOTE),
            )
        }
    }

    internal fun interpret(
        status: SelinuxStatus,
        access: AccessDecision,
    ): SelinuxPolicyloadSeqnoResult {
        val state = when {
            status.sequence % 2L != 0L -> SelinuxPolicyloadSeqnoState.INCONCLUSIVE

            status.policyload > 0L && access.seqno > 0L && status.policyload == access.seqno ->
                SelinuxPolicyloadSeqnoState.CLEAN

            status.sequence > 0L && status.policyload == 0L && access.seqno > 0L ->
                SelinuxPolicyloadSeqnoState.SUSPICIOUS

            status.policyload > 0L && access.seqno > 0L && status.policyload != access.seqno ->
                SelinuxPolicyloadSeqnoState.SUSPICIOUS

            else -> SelinuxPolicyloadSeqnoState.INCONCLUSIVE
        }
        return SelinuxPolicyloadSeqnoResult(
            state = state,
            available = true,
            probeAttempted = true,
            statusSequence = status.sequence,
            statusPolicyload = status.policyload,
            accessSeqno = access.seqno,
            processClass = access.processClass,
            notes = listOf(ZYGOTE_PRELOAD_NOTE),
        )
    }

    private fun readStatusStable(): SelinuxStatus {
        repeat(STATUS_STABLE_READ_ATTEMPTS) {
            val status = readStatusOnce()
            if (status.sequence % 2L == 0L) {
                return status
            }
            Thread.sleep(2L)
        }
        return readStatusOnce()
    }

    private fun readStatusOnce(): SelinuxStatus {
        val bytes = FileInputStream(SELINUX_STATUS).use { input ->
            val buffer = ByteArray(STATUS_SIZE_BYTES)
            val count = input.read(buffer)
            if (count < STATUS_SIZE_BYTES) {
                throw IOException("SELinux status short read: $count")
            }
            buffer
        }
        return SelinuxStatus(
            version = le32(bytes, 0),
            sequence = le32(bytes, 4),
            enforcing = le32(bytes, 8),
            policyload = le32(bytes, 12),
            denyUnknown = le32(bytes, 16),
        )
    }

    private fun queryAccessDecision(): AccessDecision {
        val processClass = readProcessClass()
        val query = "$APP_ZYGOTE_CONTEXT $ISOLATED_APP_CONTEXT $processClass"
        RandomAccessFile(SELINUX_ACCESS, "rw").use { file ->
            file.write(query.toByteArray(Charsets.US_ASCII))
            file.seek(0L)
            val buffer = ByteArray(ACCESS_RESPONSE_MAX_BYTES)
            val count = file.read(buffer)
            if (count <= 0) {
                throw IOException("SELinux access response was empty.")
            }
            val fields = String(buffer, 0, count, Charsets.US_ASCII).trim().split(Regex("\\s+"))
            if (fields.size < 6) {
                throw IOException("SELinux access response had ${fields.size} fields.")
            }
            return AccessDecision(
                processClass = processClass,
                seqno = fields[4].toLongOrNull()
                    ?: throw IOException("SELinux access seqno was not numeric."),
            )
        }
    }

    private fun readProcessClass(): Int {
        return FileInputStream(SELINUX_PROCESS_CLASS).use { input ->
            input.bufferedReader().readText().trim().toIntOrNull()
        } ?: throw IOException("SELinux process class was unreadable.")
    }

    private fun le32(bytes: ByteArray, offset: Int): Long {
        return (bytes[offset].toLong() and 0xffL) or
            ((bytes[offset + 1].toLong() and 0xffL) shl 8) or
            ((bytes[offset + 2].toLong() and 0xffL) shl 16) or
            ((bytes[offset + 3].toLong() and 0xffL) shl 24)
    }

    internal data class SelinuxStatus(
        val version: Long,
        val sequence: Long,
        val enforcing: Long,
        val policyload: Long,
        val denyUnknown: Long,
    )

    internal data class AccessDecision(
        val processClass: Int,
        val seqno: Long,
    )

    companion object {
        const val METHOD_LABEL = "App-zygote seqno oracle"
        const val STATUS_CLEAN = "Clean"
        const val STATUS_SUSPICIOUS = "Seqno split"
        const val STATUS_INCONCLUSIVE = "Info"
        const val STATUS_UNAVAILABLE = "Unavailable"

        private const val SELINUX_STATUS = "/sys/fs/selinux/status"
        private const val SELINUX_ACCESS = "/sys/fs/selinux/access"
        private const val SELINUX_PROCESS_CLASS = "/sys/fs/selinux/class/process/index"
        private const val APP_ZYGOTE_CONTEXT = "u:r:app_zygote:s0"
        private const val ISOLATED_APP_CONTEXT = "u:r:isolated_app:s0"
        private const val STATUS_SIZE_BYTES = 20
        private const val STATUS_STABLE_READ_ATTEMPTS = 3
        private const val ACCESS_RESPONSE_MAX_BYTES = 256
        private const val ZYGOTE_PRELOAD_NOTE =
            "This oracle is trusted only when produced by android:zygotePreloadName inside the dedicated app_zygote carrier."
    }
}
