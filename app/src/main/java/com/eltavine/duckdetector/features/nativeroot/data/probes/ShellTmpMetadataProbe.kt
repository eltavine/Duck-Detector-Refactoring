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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.system.ErrnoException
import android.system.Os
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup

data class ShellTmpMetadataProbeResult(
    val available: Boolean,
    val checkedCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val hitCount: Int
        get() = findings.count { it.severity != NativeRootFindingSeverity.INFO }
}

internal data class ShellTmpMetadataSample(
    val uid: Int,
    val gid: Int,
    val mode: Int,
    val inode: Long,
)

class ShellTmpMetadataProbe {

    fun run(): ShellTmpMetadataProbeResult {
        val sample = try {
            val stat = Os.lstat(SHELL_TMP_PATH)
            ShellTmpMetadataSample(
                uid = stat.st_uid,
                gid = stat.st_gid,
                mode = stat.st_mode,
                inode = stat.st_ino,
            )
        } catch (error: ErrnoException) {
            return ShellTmpMetadataProbeResult(
                available = false,
                checkedCount = CHECK_COUNT,
                findings = emptyList(),
                detail = "Could not stat $SHELL_TMP_PATH: errno=${error.errno}.",
            )
        } catch (error: Throwable) {
            return ShellTmpMetadataProbeResult(
                available = false,
                checkedCount = CHECK_COUNT,
                findings = emptyList(),
                detail = "Could not stat $SHELL_TMP_PATH: ${error.javaClass.simpleName}.",
            )
        }

        return evaluate(sample)
    }

    internal fun evaluate(
        sample: ShellTmpMetadataSample?,
    ): ShellTmpMetadataProbeResult {
        if (sample == null) {
            return ShellTmpMetadataProbeResult(
                available = false,
                checkedCount = CHECK_COUNT,
                findings = emptyList(),
                detail = "No shell tmp metadata sample was available.",
            )
        }

        val findings = buildList {
            if (sample.uid != EXPECTED_SHELL_ID || sample.gid != EXPECTED_SHELL_ID) {
                add(
                    NativeRootFinding(
                        id = "shell_tmp_owner",
                        label = "Shell tmp ownership",
                        value = "${sample.uid}:${sample.gid}",
                        detail = "Expected shell:shell (${EXPECTED_SHELL_ID}:${EXPECTED_SHELL_ID}) for $SHELL_TMP_PATH, but found ${sample.uid}:${sample.gid}.",
                        group = NativeRootGroup.PATH,
                        severity = NativeRootFindingSeverity.DANGER,
                        detailMonospace = true,
                    ),
                )
            }

            val mode = sample.mode and MODE_MASK
            if (mode != EXPECTED_MODE) {
                add(
                    NativeRootFinding(
                        id = "shell_tmp_mode",
                        label = "Shell tmp mode",
                        value = mode.toOctalMode(),
                        detail = "Expected mode ${EXPECTED_MODE.toOctalMode()} for $SHELL_TMP_PATH, but found ${mode.toOctalMode()}.",
                        group = NativeRootGroup.PATH,
                        severity = NativeRootFindingSeverity.DANGER,
                        detailMonospace = true,
                    ),
                )
            }

            if (sample.inode > HIGH_INODE_THRESHOLD) {
                add(
                    NativeRootFinding(
                        id = "shell_tmp_inode",
                        label = "Shell tmp inode",
                        value = sample.inode.toString(),
                        detail = "The inode for $SHELL_TMP_PATH is ${sample.inode}, above the heuristic review threshold $HIGH_INODE_THRESHOLD. This is weaker than owner/mode drift and can also reflect deletion or recreation history.",
                        group = NativeRootGroup.PATH,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    ),
                )
            }
        }

        return ShellTmpMetadataProbeResult(
            available = true,
            checkedCount = CHECK_COUNT,
            findings = findings,
            detail = buildString {
                append("uid=${sample.uid}, gid=${sample.gid}, mode=${(sample.mode and MODE_MASK).toOctalMode()}, inode=${sample.inode}")
            },
        )
    }

    private fun Int.toOctalMode(): String = "0" + toString(8).padStart(3, '0')

    private companion object {
        private const val SHELL_TMP_PATH = "/data/local/tmp"
        private const val EXPECTED_SHELL_ID = 2000
        private const val EXPECTED_MODE = 0x1F9 // 0771
        private const val MODE_MASK = 0x1FF
        private const val HIGH_INODE_THRESHOLD = 10000L
        private const val CHECK_COUNT = 3
    }
}
