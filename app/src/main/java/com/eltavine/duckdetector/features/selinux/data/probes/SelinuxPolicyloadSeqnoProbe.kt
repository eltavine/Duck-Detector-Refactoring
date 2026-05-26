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
import java.util.concurrent.TimeUnit

enum class SelinuxPolicyloadSeqnoState {
    CLEAN,
    SUSPICIOUS,
    INCONCLUSIVE,
    UNAVAILABLE,
}

data class SelinuxPathMetadata(
    val path: String,
    val exists: Boolean,
    val uid: Int? = null,
    val mode: String? = null,
    val rawMode: Long? = null,
    val fileType: String? = null,
    val failureReason: String? = null,
)

data class SelinuxPolicyloadSeqnoMetadataResult(
    val available: Boolean,
    val probeAttempted: Boolean,
    val statusMetadata: SelinuxPathMetadata,
    val accessMetadata: SelinuxPathMetadata,
    val failureReason: String? = null,
    val unavailableReason: String? = null,
)

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

internal fun interface SelinuxStatCommandRunner {
    fun run(
        command: List<String>,
        timeoutSeconds: Long,
    ): SelinuxStatCommandResult
}

internal data class SelinuxStatCommandResult(
    val exitCode: Int?,
    val stdout: String,
    val stderr: String,
    val timedOut: Boolean = false,
    val failureReason: String? = null,
)

class SelinuxPolicyloadSeqnoProbe {

    fun inspect(): SelinuxPolicyloadSeqnoResult {
        return inspect(
            statusReader = ::readStatusStable,
            accessDecisionReader = ::queryAccessDecision,
        )
    }

    internal fun inspect(
        statusReader: () -> SelinuxStatus,
        accessDecisionReader: () -> AccessDecision,
    ): SelinuxPolicyloadSeqnoResult {
        return runCatching {
            val status = statusReader()
            val access = accessDecisionReader()
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
        val bytes = FileInputStream(SELINUX_STATUS_PATH).use { input ->
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
        RandomAccessFile(SELINUX_ACCESS_PATH, "rw").use { file ->
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
        const val STATUS_METADATA_MISMATCH = "Metadata mismatch"
        const val STATUS_INCONCLUSIVE = "Info"
        const val STATUS_UNAVAILABLE = "Unavailable"

        const val SELINUX_STATUS_PATH = "/sys/fs/selinux/status"
        const val SELINUX_ACCESS_PATH = "/sys/fs/selinux/access"

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

class SelinuxPolicyloadSeqnoMetadataProbe internal constructor(
    private val statCommandRunner: SelinuxStatCommandRunner = ProcessSelinuxStatCommandRunner(),
) {

    fun inspect(): SelinuxPolicyloadSeqnoMetadataResult {
        val command = listOf(
            STAT_BINARY,
            "-c",
            STAT_FORMAT,
            SelinuxPolicyloadSeqnoProbe.SELINUX_STATUS_PATH,
            SelinuxPolicyloadSeqnoProbe.SELINUX_ACCESS_PATH,
        )
        val result = statCommandRunner.run(command, STAT_TIMEOUT_SECONDS)
        return parseStatMetadata(result)
    }

    private fun parseStatMetadata(result: SelinuxStatCommandResult): SelinuxPolicyloadSeqnoMetadataResult {
        val parsed = linkedMapOf<String, SelinuxPathMetadata>()
        result.stdout
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                val fields = line.split('\t')
                if (fields.size < STAT_FIELD_COUNT) {
                    return@forEach
                }
                val path = fields[0].trim()
                if (path !in EXPECTED_METADATA_PATHS) {
                    return@forEach
                }
                val uidText = fields[1].trim()
                val rawModeText = fields[2].trim()
                val uid = uidText.toIntOrNull()
                val rawMode = rawModeText.toLongOrNull(radix = 16)
                parsed[path] = SelinuxPathMetadata(
                    path = path,
                    exists = true,
                    uid = uid,
                    mode = rawMode?.let(::permissionMode),
                    rawMode = rawMode,
                    fileType = rawMode?.let(::fileType),
                    failureReason = when {
                        uid == null -> "stat uid was not numeric: $uidText"
                        rawMode == null -> "stat raw mode was not hex: $rawModeText"
                        else -> null
                    },
                )
            }

        val commandFailureReason = result.commandFailureReason()
        val status = parsed[SelinuxPolicyloadSeqnoProbe.SELINUX_STATUS_PATH] ?: SelinuxPathMetadata(
            path = SelinuxPolicyloadSeqnoProbe.SELINUX_STATUS_PATH,
            exists = false,
        )
        val access = parsed[SelinuxPolicyloadSeqnoProbe.SELINUX_ACCESS_PATH] ?: SelinuxPathMetadata(
            path = SelinuxPolicyloadSeqnoProbe.SELINUX_ACCESS_PATH,
            exists = false,
        )
        val parsedMetadataCount = parsed.size
        val unavailableReason = unavailableReason(
            status = status,
            access = access,
            commandFailureReason = commandFailureReason,
            parsedMetadataCount = parsedMetadataCount,
        )
        val failureReason = if (unavailableReason == null) {
            failureReason(status, access)
        } else {
            null
        }
        return SelinuxPolicyloadSeqnoMetadataResult(
            available = unavailableReason == null,
            probeAttempted = true,
            statusMetadata = status,
            accessMetadata = access,
            failureReason = failureReason,
            unavailableReason = unavailableReason,
        )
    }

    private fun SelinuxStatCommandResult.commandFailureReason(): String? {
        val reasons = buildList {
            failureReason?.takeIf { it.isNotBlank() }?.let(::add)
            if (timedOut) {
                add("stat command timed out")
            }
            exitCode?.takeIf { it != 0 }?.let { add("stat exit=$it") }
            if (stdout.isBlank()) {
                add("stat produced no output")
            }
            stderr.takeIf { it.isNotBlank() }?.let { add("stderr=${it.take(MAX_STAT_DIAGNOSTIC_CHARS)}") }
        }
        return reasons.takeIf { it.isNotEmpty() }?.joinToString("; ")
    }

    private fun unavailableReason(
        status: SelinuxPathMetadata,
        access: SelinuxPathMetadata,
        commandFailureReason: String?,
        parsedMetadataCount: Int,
    ): String? {
        if (parsedMetadataCount == 0) {
            return commandFailureReason ?: "stat returned no SELinux metadata"
        }
        val parseFailures = listOf(status, access)
            .filter { it.exists }
            .mapNotNull { metadata ->
                metadata.failureReason?.let { "${metadata.path}: $it" }
            }
        return parseFailures.takeIf { it.isNotEmpty() }?.joinToString(
            prefix = "stat metadata parse failed: ",
            separator = "; ",
        )
    }

    private fun failureReason(
        status: SelinuxPathMetadata,
        access: SelinuxPathMetadata,
    ): String? {
        val failures = buildList {
            listOf(status, access).forEach { metadata ->
                if (!metadata.exists) {
                    add("${metadata.path} missing")
                    return@forEach
                }
                if (metadata.uid != EXPECTED_METADATA_UID) {
                    add("${metadata.path} uid=${metadata.uid ?: "unreadable"} expected=$EXPECTED_METADATA_UID")
                }
                val expectedMode = expectedPermissionMode(metadata.path)
                if (metadata.mode != expectedMode) {
                    add("${metadata.path} mode=${metadata.mode ?: "unreadable"} expected=$expectedMode")
                }
                if (metadata.fileType != EXPECTED_METADATA_FILE_TYPE) {
                    add(
                        "${metadata.path} type=${metadata.fileType ?: "unreadable"} " +
                            "expected=$EXPECTED_METADATA_FILE_TYPE",
                    )
                }
            }
        }.distinct()
        return failures.takeIf { it.isNotEmpty() }?.joinToString(
            prefix = "metadata mismatch: ",
            separator = "; ",
        )
    }

    private fun permissionMode(rawMode: Long): String {
        return (rawMode and PERMISSION_BITS_MASK).toString(radix = 8).padStart(3, '0')
    }

    private fun fileType(rawMode: Long): String {
        return when (rawMode and FILE_TYPE_BITS_MASK) {
            REGULAR_FILE_BITS -> "regular"
            DIRECTORY_BITS -> "directory"
            CHARACTER_DEVICE_BITS -> "character"
            BLOCK_DEVICE_BITS -> "block"
            SYMLINK_BITS -> "symlink"
            SOCKET_BITS -> "socket"
            FIFO_BITS -> "fifo"
            else -> "unknown"
        }
    }

    private fun expectedPermissionMode(path: String): String {
        return when (path) {
            SelinuxPolicyloadSeqnoProbe.SELINUX_ACCESS_PATH -> EXPECTED_ACCESS_METADATA_MODE
            else -> EXPECTED_STATUS_METADATA_MODE
        }
    }

    private companion object {
        private const val STAT_BINARY = "/system/bin/stat"
        private const val STAT_FORMAT = "%n\t%u\t%f"
        private const val STAT_TIMEOUT_SECONDS = 2L
        private const val STAT_FIELD_COUNT = 3
        private const val EXPECTED_METADATA_UID = 0
        private const val EXPECTED_STATUS_METADATA_MODE = "444"
        private const val EXPECTED_ACCESS_METADATA_MODE = "666"
        private const val EXPECTED_METADATA_FILE_TYPE = "regular"
        private const val PERMISSION_BITS_MASK = 0x1FFL
        private const val FILE_TYPE_BITS_MASK = 0xF000L
        private const val FIFO_BITS = 0x1000L
        private const val CHARACTER_DEVICE_BITS = 0x2000L
        private const val DIRECTORY_BITS = 0x4000L
        private const val BLOCK_DEVICE_BITS = 0x6000L
        private const val REGULAR_FILE_BITS = 0x8000L
        private const val SYMLINK_BITS = 0xA000L
        private const val SOCKET_BITS = 0xC000L
        private const val MAX_STAT_DIAGNOSTIC_CHARS = 160
        private val EXPECTED_METADATA_PATHS = setOf(
            SelinuxPolicyloadSeqnoProbe.SELINUX_STATUS_PATH,
            SelinuxPolicyloadSeqnoProbe.SELINUX_ACCESS_PATH,
        )
    }
}

private class ProcessSelinuxStatCommandRunner : SelinuxStatCommandRunner {

    override fun run(
        command: List<String>,
        timeoutSeconds: Long,
    ): SelinuxStatCommandResult {
        return runCatching {
            val process = ProcessBuilder(command).start()
            val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                return@runCatching SelinuxStatCommandResult(
                    exitCode = null,
                    stdout = "",
                    stderr = "",
                    timedOut = true,
                )
            }
            SelinuxStatCommandResult(
                exitCode = process.exitValue(),
                stdout = process.inputStream.bufferedReader().use { it.readText().trim() },
                stderr = process.errorStream.bufferedReader().use { it.readText().trim() },
            )
        }.getOrElse { throwable ->
            SelinuxStatCommandResult(
                exitCode = null,
                stdout = "",
                stderr = "",
                failureReason = throwable.message ?: throwable.javaClass.simpleName,
            )
        }
    }
}
