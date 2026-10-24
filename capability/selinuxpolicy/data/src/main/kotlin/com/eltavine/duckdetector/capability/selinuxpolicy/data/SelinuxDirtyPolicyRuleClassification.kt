package com.eltavine.duckdetector.capability.selinuxpolicy.data

/** Shared alert eligibility for the Native, Java and direct selinuxfs observations. */
public object SelinuxDirtyPolicyRuleClassification {
    private val alertEligible = setOf(
        "system_server execmem",
        "shell -> su transition",
        "adbd -> adbroot binder",
        "untrusted_app -> magisk binder",
        "untrusted_app -> ksu_file read",
        "untrusted_app -> lsposed_file read",
        "magisk -> droidspacesd dyntransition",
        "su -> droidspacesd dyntransition",
        "system_server -> droidspacesd binder",
        "msd_app -> msd_daemon connectto",
        "msd_daemon -> msd_daemon connectto",
        "msd_daemon -> selinuxfs read",
        "msd_daemon -> configfs dir search",
        "msd_daemon -> configfs file write",
        "untrusted_app -> xposed_data read",
        "zygote -> adb_data_file search",
        "rootfs -> tmpfs associate",
        "kernel -> tmpfs fifo open",
        "kernel -> adb_data_file read",
    )

    public fun isAlertEligible(edge: String): Boolean = edge in alertEligible
}
