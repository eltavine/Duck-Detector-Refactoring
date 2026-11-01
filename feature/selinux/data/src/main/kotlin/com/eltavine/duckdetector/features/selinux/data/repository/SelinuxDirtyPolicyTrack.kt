package com.eltavine.duckdetector.features.selinux.data.repository

internal enum class DirtyPolicyTrackSource {
    NATIVE,
    JAVA,
}

internal data class DirtyPolicyTrack(
    val label: String,
    val trusted: Boolean,
    val available: Boolean,
    val probeAttempted: Boolean,
    val carrierContext: String?,
    val carrierMatchesExpected: Boolean,
    val controlsPassed: Boolean,
    val stable: Boolean,
    val queryMethod: String,
    val accessControlAllowed: Boolean?,
    val negativeControlRejected: Boolean?,
    val systemServerExecmemAllowed: Boolean?,
    val fsckSysAdminAllowed: Boolean?,
    val shellSuTransitionAllowed: Boolean?,
    val adbdAdbrootBinderCallAllowed: Boolean?,
    val magiskBinderCallAllowed: Boolean?,
    val ksuFileReadAllowed: Boolean?,
    val lsposedFileReadAllowed: Boolean?,
    val magiskDroidspacesdTransitionAllowed: Boolean?,
    val suDroidspacesdTransitionAllowed: Boolean?,
    val systemServerDroidspacesdBinderCallAllowed: Boolean?,
    val msdAppDaemonConnectAllowed: Boolean?,
    val msdDaemonSelfConnectAllowed: Boolean?,
    val msdDaemonSelinuxfsReadAllowed: Boolean?,
    val msdDaemonConfigfsDirSearchAllowed: Boolean?,
    val msdDaemonConfigfsFileWriteAllowed: Boolean?,
    val xposedDataFileReadAllowed: Boolean?,
    val zygoteAdbDataSearchAllowed: Boolean?,
    val failureReason: String?,
    val additionalRules: Map<String, Boolean>,
) {
    val reportable: Boolean
        get() = available && probeAttempted && carrierMatchesExpected

    fun describe(verdict: Boolean?): String {
        val status = when (verdict) {
            true -> "Allowed"
            false -> "Denied"
            null -> "Unavailable"
        }
        return buildString {
            append(status)
            append(" carrier=")
            append(carrierContext ?: "<unreadable>")
            append(" match=")
            append(if (carrierMatchesExpected) "yes" else "no")
            append(" controls=")
            append(if (controlsPassed) "passed" else "failed")
            append(" stable=")
            append(if (stable) "yes" else "no")
            append(" trusted=")
            append(if (trusted) "yes" else "no")
            append(" query=")
            append(queryMethod.ifBlank { "<unavailable>" })
            failureReason?.takeIf { it.isNotBlank() }?.let {
                append(" reason=")
                append(it)
            }
        }
    }
}
