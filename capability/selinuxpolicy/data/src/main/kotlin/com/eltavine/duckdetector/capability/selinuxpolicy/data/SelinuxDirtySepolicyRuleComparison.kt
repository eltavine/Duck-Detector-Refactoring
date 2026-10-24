package com.eltavine.duckdetector.capability.selinuxpolicy.data

/** Contradictory, fully parsed replies to the same query within one policy epoch. */
public fun SelinuxDirtySepolicyRawSnapshot.sameEpochDecisionSplits(): List<String> {
    if (!controlsPassed) return emptyList()
    return observations.groupBy { it.query }.mapNotNull { (query, samples) ->
        if (samples.size != 2 || samples[0].outcome == samples[1].outcome ||
            samples.any { it.outcome != "ALLOWED" && it.outcome != "DENIED" }) return@mapNotNull null
        val first = samples[0].response?.let(SelinuxRawAccess::parse)
        val second = samples[1].response?.let(SelinuxRawAccess::parse)
        if (first != null && second != null && first.seqno == second.seqno &&
            (first.flags and 1u) == 0u && (second.flags and 1u) == 0u) query else null
    }
}

/** Interpret the same result slots populated by the existing Dirty Policy rule plan. */
internal fun SelinuxContextValiditySnapshot.comparableDirtyPolicyRules(): Map<String, Boolean?> = buildMap {
    put("system_server execmem", javaDirtyPolicySystemServerExecmemAllowed)
    put("shell -> su transition", javaDirtyPolicyShellSuTransitionAllowed)
    put("adbd -> adbroot binder", javaDirtyPolicyAdbdAdbrootBinderCallAllowed)
    put("untrusted_app -> magisk binder", javaDirtyPolicyMagiskBinderCallAllowed)
    put("untrusted_app -> ksu_file read", javaDirtyPolicyKsuFileReadAllowed)
    put("untrusted_app -> lsposed_file read", javaDirtyPolicyLsposedFileReadAllowed)
    put("magisk -> droidspacesd dyntransition", javaDirtyPolicyMagiskDroidspacesdTransitionAllowed)
    put("su -> droidspacesd dyntransition", javaDirtyPolicySuDroidspacesdTransitionAllowed)
    put("system_server -> droidspacesd binder", javaDirtyPolicySystemServerDroidspacesdBinderCallAllowed)
    put("msd_app -> msd_daemon connectto", javaDirtyPolicyMsdAppDaemonConnectAllowed)
    put("msd_daemon -> msd_daemon connectto", javaDirtyPolicyMsdDaemonSelfConnectAllowed)
    put("msd_daemon -> selinuxfs read", javaDirtyPolicyMsdDaemonSelinuxfsReadAllowed)
    put("msd_daemon -> configfs dir search", javaDirtyPolicyMsdDaemonConfigfsDirSearchAllowed)
    put("msd_daemon -> configfs file write", javaDirtyPolicyMsdDaemonConfigfsFileWriteAllowed)
    put("untrusted_app -> xposed_data read", javaDirtyPolicyXposedDataFileReadAllowed)
    put("zygote -> adb_data_file search", javaDirtyPolicyZygoteAdbDataSearchAllowed)
    javaDirtyPolicyAdditionalRules.forEach { (name, allowed) ->
        if (name != "dex2oat -> dex2oat_exec execute_no_trans") put(name, allowed)
    }
}
