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

import android.os.Process
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeBridge
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeEntry
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativePath
import com.eltavine.duckdetector.features.nativeroot.data.native.CgroupProcessLeakNativeSnapshot
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFinding
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootFindingSeverity
import com.eltavine.duckdetector.features.nativeroot.domain.NativeRootGroup
import java.io.File

data class CgroupProcessLeakProbeResult(
    val available: Boolean,
    val pathCheckCount: Int,
    val accessiblePathCount: Int,
    val processCheckedCount: Int,
    val procDeniedCount: Int,
    val findings: List<NativeRootFinding>,
    val detail: String,
) {
    val hitCount: Int
        get() = findings.count { it.severity != NativeRootFindingSeverity.INFO }
}

internal data class CgroupProcessJavaView(
    val checkedPathCount: Int,
    val accessiblePaths: Set<String>,
    val pidEntriesByPath: Map<String, Set<Int>>,
) {
    val available: Boolean
        get() = accessiblePaths.isNotEmpty()
}

internal data class CgroupProcessRule(
    val token: String,
    val label: String,
)

internal data class CgroupProcessLiveness(
    val confirmed: Boolean,
    val evidence: List<String>,
)

class CgroupProcessLeakProbe(
    private val nativeBridge: CgroupProcessLeakNativeBridge = CgroupProcessLeakNativeBridge(),
) {

    fun run(): CgroupProcessLeakProbeResult {
        val nativeSnapshot = nativeBridge.collectSnapshot()
        val javaView = collectJavaView(
            nativeSnapshot.paths.map(CgroupProcessLeakNativePath::path).ifEmpty { candidateUidPaths() },
        )
        return evaluate(
            nativeSnapshot = nativeSnapshot,
            javaView = javaView,
            selfPid = Process.myPid(),
        )
    }

    internal fun evaluate(
        nativeSnapshot: CgroupProcessLeakNativeSnapshot,
        javaView: CgroupProcessJavaView,
        selfPid: Int = -1,
    ): CgroupProcessLeakProbeResult {
        val findings = mutableListOf<NativeRootFinding>()
        val dedupe = linkedSetOf<String>()
        val javaPidsByPath = javaView.pidEntriesByPath
        val nativePathsByPath = nativeSnapshot.paths.associateBy(CgroupProcessLeakNativePath::path)

        nativeSnapshot.entries.sortedWith(compareBy({ it.uidPath }, { it.pid })).forEach { entry ->
            if (entry.pid == selfPid) {
                return@forEach
            }

            val rule = suspiciousRules.firstOrNull { entry.matchText.contains(it.token) }
            val contextRule =
                suspiciousContextRules.firstOrNull { entry.contextText.contains(it.token) }
            val javaVisible = javaPidsByPath[entry.uidPath]?.contains(entry.pid) == true
            val liveness = entry.liveness()
            val uidMismatch = entry.procUid != null && entry.procUid != entry.cgroupUid

            if (uidMismatch) {
                val key = "uid-mismatch|${entry.uidPath}|${entry.pid}|${entry.procUid}"
                if (dedupe.add(key)) {
                    findings += NativeRootFinding(
                        id = "cgroup_uid_mismatch_${entry.pid}",
                        label = "Cgroup UID mismatch",
                        value = "uid_${entry.cgroupUid} vs ${entry.procUid}",
                        detail = buildString {
                            append("Cgroup path ")
                            append(entry.uidPath)
                            append(" places PID ")
                            append(entry.pid)
                            append(" under uid_")
                            append(entry.cgroupUid)
                            append(", but /proc/")
                            append(entry.pid)
                            append("/status reported uid=")
                            append(entry.procUid)
                            append(".")
                            append(entry.livenessDetail(liveness))
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    )
                }
            }

            if (rule != null) {
                val key = "token|${rule.token}|${entry.uidPath}|${entry.pid}"
                if (dedupe.add(key)) {
                    findings += NativeRootFinding(
                        id = "cgroup_token_${rule.token}_${entry.pid}",
                        label = rule.label,
                        value = "PID ${entry.pid}",
                        detail = buildString {
                            append("Native cgroup scan exposed a suspicious process token under ")
                            append(entry.uidPath)
                            append('.')
                            append(entry.livenessDetail(liveness))
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    )
                }
            }

            if (contextRule != null) {
                val key = "context|${contextRule.token}|${entry.uidPath}|${entry.pid}"
                if (dedupe.add(key)) {
                    findings += NativeRootFinding(
                        id = "cgroup_context_${contextRule.token}_${entry.pid}",
                        label = when {
                            rule?.label == "LSPosed companion residue" &&
                                    contextRule.token == ":su:" -> "LSPosed root-context process"

                            else -> contextRule.label
                        },
                        value = "PID ${entry.pid}",
                        detail = buildString {
                            append("Native cgroup scan exposed PID ")
                            append(entry.pid)
                            append(" under ")
                            append(entry.uidPath)
                            append(" with suspicious SELinux context ")
                            append(entry.procContext.ifBlank { "<empty>" })
                            append('.')
                            append(entry.livenessDetail(liveness))
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = NativeRootFindingSeverity.WARNING,
                        detailMonospace = true,
                    )
                }
            }

            val shouldCheckVisibility =
                rule != null || contextRule != null ||
                        uidMismatch
            if (shouldCheckVisibility && !javaVisible) {
                val pathState = nativePathsByPath[entry.uidPath]
                val key = "visibility|${entry.uidPath}|${entry.pid}"
                if (dedupe.add(key)) {
                    val confirmedHiddenSuspicious = liveness.confirmed && (rule != null || contextRule != null)
                    findings += NativeRootFinding(
                        id = "cgroup_visibility_${entry.pid}",
                        label = "Selective cgroup visibility",
                        value = "PID ${entry.pid}",
                        detail = buildString {
                            append("Java File view did not expose PID ")
                            append(entry.pid)
                            append(" under ")
                            append(entry.uidPath)
                            append(", but native getdents did")
                            pathState?.takeIf { it.accessible }?.let {
                                append(" (native pidCount=")
                                append(it.pidCount)
                                append(')')
                            }
                            if (liveness.confirmed) {
                                append("; native syscall liveness confirmed PID existence")
                            } else {
                                append("; syscall liveness did not confirm PID existence")
                            }
                            append('.')
                            append(entry.livenessDetail(liveness))
                            append(entry.describe())
                        },
                        group = NativeRootGroup.PROCESS,
                        severity = if (confirmedHiddenSuspicious) {
                            NativeRootFindingSeverity.DANGER
                        } else {
                            NativeRootFindingSeverity.WARNING
                        },
                        detailMonospace = true,
                    )
                }
            }
        }

        val pathCheckCount =
            nativeSnapshot.pathCheckCount.takeIf { it > 0 } ?: javaView.checkedPathCount
        val accessiblePathCount =
            maxOf(nativeSnapshot.accessiblePathCount, javaView.accessiblePaths.size)
        val processCheckedCount = maxOf(
            nativeSnapshot.processCount,
            javaView.pidEntriesByPath.values.sumOf { it.size },
        )

        return CgroupProcessLeakProbeResult(
            available = nativeSnapshot.available,
            pathCheckCount = pathCheckCount,
            accessiblePathCount = accessiblePathCount,
            processCheckedCount = processCheckedCount,
            procDeniedCount = nativeSnapshot.procDeniedCount,
            findings = findings,
            detail = buildString {
                append("Checked ")
                append(pathCheckCount)
                append(" candidate uid path(s); native accessible=")
                append(accessiblePathCount)
                append(", native pid entries=")
                append(processCheckedCount)
                append(", native proc denied=")
                append(nativeSnapshot.procDeniedCount)
                append(", Java visible paths=")
                append(javaView.accessiblePaths.size)
                append('.')
            },
        )
    }

    internal fun collectJavaView(
        uidPaths: List<String>,
    ): CgroupProcessJavaView {
        val accessiblePaths = linkedSetOf<String>()
        val pidEntriesByPath = linkedMapOf<String, Set<Int>>()

        uidPaths.forEach { uidPath ->
            val entries = runCatching {
                File(uidPath).listFiles()
                    ?.asSequence()
                    ?.mapNotNull { file ->
                        file.name.removePrefix("pid_")
                            .takeIf { file.isDirectory && file.name.startsWith("pid_") }
                            ?.toIntOrNull()
                    }
                    ?.toCollection(linkedSetOf())
            }.getOrNull() ?: return@forEach

            accessiblePaths += uidPath
            pidEntriesByPath[uidPath] = entries
        }

        return CgroupProcessJavaView(
            checkedPathCount = uidPaths.size,
            accessiblePaths = accessiblePaths,
            pidEntriesByPath = pidEntriesByPath,
        )
    }

    internal fun candidateUidPaths(
        currentUid: Int = Process.myUid(),
    ): List<String> {
        val uids = linkedSetOf(0, 1000, 2000, currentUid)
        return buildList {
            uids.forEach { uid ->
                add("/sys/fs/cgroup/uid_$uid")
                add("/sys/fs/cgroup/apps/uid_$uid")
                add("/sys/fs/cgroup/system/uid_$uid")
                add("/dev/cg2_bpf/uid_$uid")
                add("/dev/cg2_bpf/apps/uid_$uid")
                add("/dev/cg2_bpf/system/uid_$uid")
                add("/acct/uid_$uid")
                add("/dev/memcg/apps/uid_$uid")
            }
        }
    }

    private val CgroupProcessLeakNativeEntry.matchText: String
        get() = buildString {
            append(comm.lowercase())
            append(' ')
            append(cmdline.lowercase())
        }

    private val CgroupProcessLeakNativeEntry.contextText: String
        get() = procContext.lowercase()

    private fun CgroupProcessLeakNativeEntry.describe(): String {
        return buildString {
            append("\nuidPath=")
            append(uidPath)
            append("\npid=")
            append(pid)
            append("\ncgroupUid=")
            append(cgroupUid)
            append("\nprocUid=")
            append(procUid ?: -1)
            startTimeTicks?.let {
                append("\nstartTimeTicks=")
                append(it)
            }
            killErrno?.let {
                append("\nkillErrno=")
                append(it)
            }
            sid?.let {
                append("\ngetsid=")
                append(it)
            }
            sidErrno?.let {
                append("\ngetsidErrno=")
                append(it)
            }
            pgid?.let {
                append("\ngetpgid=")
                append(it)
            }
            pgidErrno?.let {
                append("\ngetpgidErrno=")
                append(it)
            }
            schedulerPolicy?.let {
                append("\nschedulerPolicy=")
                append(it)
            }
            schedulerErrno?.let {
                append("\nschedulerErrno=")
                append(it)
            }
            pidfdErrno?.let {
                append("\npidfdErrno=")
                append(it)
            }
            if (procContext.isNotBlank()) {
                append("\nprocContext=")
                append(procContext)
            }
            if (comm.isNotBlank()) {
                append("\ncomm=")
                append(comm)
            }
            if (cmdline.isNotBlank()) {
                append("\ncmdline=")
                append(cmdline.replace('\u0000', ' '))
            }
        }
    }

    private fun CgroupProcessLeakNativeEntry.liveness(): CgroupProcessLiveness {
        val evidence = buildList {
            if (pidfdErrno == 0) {
                add("pidfd_open")
            }
            when (killErrno) {
                0 -> add("kill(0)=0")
                ERRNO_PERMISSION_DENIED -> add("kill(0)=EPERM")
            }
            if (sidErrno == 0 && sid != null) {
                add("getsid=$sid")
            }
            if (pgidErrno == 0 && pgid != null) {
                add("getpgid=$pgid")
            }
            when {
                schedulerErrno == 0 && schedulerPolicy != null ->
                    add("sched_getscheduler=$schedulerPolicy")

                schedulerErrno == ERRNO_PERMISSION_DENIED ->
                    add("sched_getscheduler=EPERM")
            }
        }
        return CgroupProcessLiveness(
            confirmed = evidence.isNotEmpty(),
            evidence = evidence,
        )
    }

    private fun CgroupProcessLeakNativeEntry.livenessDetail(
        liveness: CgroupProcessLiveness,
    ): String {
        return buildString {
            append("\nLiveness: ")
            if (liveness.confirmed) {
                append(liveness.evidence.joinToString())
            } else {
                append("unconfirmed")
            }
        }
    }

    private companion object {
        private const val ERRNO_PERMISSION_DENIED = 1

        private val suspiciousRules = listOf(
            CgroupProcessRule("lspd", "LSPosed companion residue"),
            CgroupProcessRule("lsposed", "LSPosed companion residue"),
            CgroupProcessRule("zygisk", "Zygisk residue process"),
            CgroupProcessRule("riru", "Riru residue process"),
            CgroupProcessRule("shamiko", "Shamiko residue process"),
            CgroupProcessRule("xposed", "Xposed residue process"),
        )

        private val suspiciousContextRules = listOf(
            CgroupProcessRule(":su:", "Root-domain process context"),
            CgroupProcessRule("magisk", "Magisk process context"),
            CgroupProcessRule("kernelsu", "KernelSU process context"),
            CgroupProcessRule("apatch", "APatch process context"),
            CgroupProcessRule("unconfined", "Unconfined process context"),
            CgroupProcessRule("permissive", "Permissive process context"),
        )
    }
}
