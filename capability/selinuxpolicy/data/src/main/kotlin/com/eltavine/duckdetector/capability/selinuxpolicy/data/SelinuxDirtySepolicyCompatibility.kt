package com.eltavine.duckdetector.capability.selinuxpolicy.data

/** DirtySepolicy 2.2's observable outcome, distinct from Duck's security attribution. */
public enum class SelinuxDirtySepolicyCompatibilityVerdict {
    NOT_COLLECTED,
    OK,
    WARNING,
    ERROR,
    INCONCLUSIVE,
}

public data class SelinuxDirtySepolicyCompatibilityResult(
    val verdict: SelinuxDirtySepolicyCompatibilityVerdict = SelinuxDirtySepolicyCompatibilityVerdict.NOT_COLLECTED,
    val reasons: List<String> = emptyList(),
)

/**
 * Interpret the existing Raw/context/status measurements in the exact order of upstream doCheck().
 * The collection remains in Duck's isolated probes. This interpreter never repeats a syscall.
 */
internal object SelinuxDirtySepolicyCompatibility {
    fun evaluate(
        carrier: SelinuxContextValiditySnapshot,
        raw: SelinuxDirtySepolicyRawSnapshot,
        status: SelinuxStatusHeader?,
        isUserBuild: Boolean,
        kernelRelease: String?,
    ): SelinuxDirtySepolicyCompatibilityResult {
        fun result(verdict: SelinuxDirtySepolicyCompatibilityVerdict, message: String) =
            SelinuxDirtySepolicyCompatibilityResult(verdict, listOf(message))

        fun error(message: String) = result(SelinuxDirtySepolicyCompatibilityVerdict.ERROR, message)
        fun unknown(message: String) = result(SelinuxDirtySepolicyCompatibilityVerdict.INCONCLUSIVE, message)

        // doPreload() checks UID before calling doCheck(). No supplied UID mismatch may be ignored.
        if (carrier.failureReason?.startsWith("UID mismatch:") == true) return error(carrier.failureReason)
        if (carrier.selinuxEnabled == false) return error("SELinux is disabled")
        if (carrier.selinuxEnabled == null) return error("SELinux enabled state unavailable")
        val context = carrier.carrierContext
        if (context == null || !context.startsWith(APP_ZYGOTE_PREFIX)) {
            return error("unexpected SELinux context: $context")
        }
        if (carrier.pidContextMatchesCurrent != true) return error("PID context mismatch or unreadable")
        if (carrier.procSelfContextMatchesCurrent != true) return error("/proc/self context mismatch or unreadable")

        class Incomplete(val detail: String, val broken: Boolean) : RuntimeException()
        val samples = raw.observations.groupBy { it.query }
        fun access(source: String, target: String, clazz: String, permission: String): Boolean {
            val key = "$source -> $target:$clazz $permission"
            val pair = samples[key].orEmpty()
            if (pair.size != 2) throw Incomplete("missing repeated samples: $key", false)
            if (pair.any { it.outcome == "INVALID_ACCESS_RESULT" }) {
                throw Incomplete("Invalid access result: $key", true)
            }
            if (pair.any { it.outcome == "UNAVAILABLE" }) {
                throw Incomplete("access failed: $key", true)
            }
            if (pair[0].outcome != pair[1].outcome) {
                throw Incomplete("unstable access response: $key", false)
            }
            return when (pair[0].outcome) {
                "ALLOWED" -> true
                "DENIED", "INVALID_CONTEXT_EINVAL" -> false
                else -> throw Incomplete("unrecognized access outcome: $key", false)
            }
        }

        fun exists(value: String): Boolean {
            val observation = raw.contextChecks.firstOrNull { it.context == value }
                ?: throw Incomplete("context not collected: $value", false)
            // Duck may continue through independently controlled fallbacks after an I/O error.
            // Upstream contextExists() only falls back on EINVAL; every other failure is terminal.
            when (observation.contextNode) {
                "VALID" -> return if (observation.verifiedBy == SelinuxRawContextSource.CONTEXT_NODE) true
                    else throw Incomplete("context node not trusted: $value", false)
                "INVALID" -> Unit // write EINVAL: upstream proceeds to class=0
                else -> throw Incomplete(
                    "context node failed: $value (${observation.contextNode})",
                    observation.contextNode.startsWith("UNAVAILABLE"),
                )
            }
            when (observation.accessNode) {
                "VALID" -> return if (observation.verifiedBy == SelinuxRawContextSource.ACCESS_CLASS_ZERO) true
                    else throw Incomplete("class=0 result not trusted: $value", false)
                "INVALID" -> Unit // write EINVAL: upstream proceeds to attr/current
                "INVALID_ACCESS_RESULT" -> throw Incomplete("invalid class=0 response: $value", true)
                else -> throw Incomplete(
                    "class=0 failed: $value (${observation.accessNode})",
                    observation.accessNode.startsWith("UNAVAILABLE"),
                )
            }
            return when (observation.attrCurrent) {
                SelinuxProcAttrCurrentResult.OUTCOME_CONTEXT_RECOGNIZED ->
                    if (observation.verifiedBy == SelinuxRawContextSource.ATTR_CURRENT) true
                    else throw Incomplete("attr/current positive not trusted: $value", false)
                SelinuxProcAttrCurrentResult.OUTCOME_NORMAL_EINVAL -> false
                "UNAVAILABLE", "SKIPPED", "UNTRUSTED" ->
                    throw Incomplete("attr/current unavailable: $value (${observation.attrCurrent})", false)
                else -> throw Incomplete("attr/current failed: $value (${observation.attrCurrent})", true)
            }
        }

        val warnings = mutableListOf<String>()
        try {
            if (!access("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent")) {
                return error("cannot check SELinux access")
            }
            if (!access("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context")) {
                return error("cannot check SELinux context")
            }
            // Upstream isSELinuxEnforced() folds read failures to false; keep that distinction in the reason.
            if (carrier.selinuxEnforced != true) warnings += if (carrier.selinuxEnforced == false) {
                "SELinux is permissive"
            } else {
                "SELinux enforcing unreadable (upstream treats this as permissive)"
            }

            if (access("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
                warnings += "system_server can execmem"
            }
            if (isUserBuild && access("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
                warnings += "found AOSP su in user build"
            }
            if (exists("u:r:adbroot:s0")) warnings += "found adb_root"

            if (exists("u:r:magisk:s0") || exists("u:object_r:magisk_file:s0") ||
                access("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate") ||
                access("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) {
                warnings += "found Magisk"
            }
            if (exists("u:r:ksu:s0") || exists("u:object_r:ksu_file:s0") ||
                access("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read")) {
                warnings += "found KernelSU"
            }
            if (exists("u:object_r:lsposed_file:s0") ||
                access("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")) {
                warnings += "found LSPosed"
            }
            if (exists("u:object_r:xposed_data:s0") || exists("u:object_r:xposed_file:s0") ||
                access("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
                warnings += "found Xposed"
            }
            if (access("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
                warnings += "found ZygiskNext"
            }
        } catch (problem: Incomplete) {
            return if (problem.broken) error(problem.detail) else unknown(problem.detail)
        }

        if (status == null) return error("read_status failed or status header unavailable")
        if (status.version != 1L) return error("unknown status version: ${status.version}")
        if (status.enforcing != 1L) warnings += "enforcing=${status.enforcing}"
        if (status.denyUnknown != 1L) warnings += "deny_unknown=${status.denyUnknown}"

        val release = Regex("^(\\d+)\\.(\\d+)").find(kernelRelease.orEmpty())
        if (release == null) return error("kernel version unavailable for DirtySepolicy initial baseline")
        val major = release.groupValues[1].toIntOrNull()
        val minor = release.groupValues[2].toIntOrNull()
        if (major == null || minor == null) return error("invalid kernel version: $kernelRelease")
        val newKernel = major > 6 || (major == 6 && minor >= 10)
        if (if (newKernel) status.policyload != 1L || status.sequence != 4L
            else status.policyload != 0L || status.sequence != 0L) {
            warnings += "sequence=${status.sequence} policyload=${status.policyload}"
        }
        val avd = raw.avdSeqno ?: return error("avdSeqNo access failed or malformed")
        val rawEpochs = raw.observations.mapNotNull { it.response?.let(SelinuxRawAccess::parse)?.seqno }.distinct()
        if (rawEpochs.size > 1) return unknown("Raw access policy epoch changed during collection")
        if (avd != 1L) warnings += "avdSeqNo=$avd"
        return if (warnings.isEmpty()) SelinuxDirtySepolicyCompatibilityResult(
            SelinuxDirtySepolicyCompatibilityVerdict.OK, listOf("no dirty sepolicy found"))
        else SelinuxDirtySepolicyCompatibilityResult(SelinuxDirtySepolicyCompatibilityVerdict.WARNING, warnings)
    }
}
