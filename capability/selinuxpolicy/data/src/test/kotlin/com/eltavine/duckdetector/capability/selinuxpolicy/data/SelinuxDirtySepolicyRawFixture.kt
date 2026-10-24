package com.eltavine.duckdetector.capability.selinuxpolicy.data

abstract class SelinuxDirtySepolicyRawFixture {
    protected val probe = SelinuxDirtySepolicyRawProbe()
    protected val carrier = SelinuxContextValiditySnapshot(
        available = true,
        carrierMatchesExpected = true,
        carrierContext = "u:r:app_zygote:s0:c512,c768",
    )

    protected fun response(allowed: Boolean) = "${if (allowed) "1" else "0"} ffffffff 0 ffffffff 1 0"

    protected fun lookup(source: String, target: String, clazz: String, permission: String): String {
        val positive = (source == "u:r:app_zygote:s0" && permission in setOf("setcurrent", "check_context")) ||
            (source == "u:r:app_zygote:s0" && target == "u:r:isolated_app:s0" && permission == "dyntransition")
        return response(positive)
    }

    protected fun inspect(
        snapshot: SelinuxContextValiditySnapshot = carrier,
        check: (String, String, String, String) -> String = ::lookup,
        queryClassZero: (String, String) -> String = { _, _ -> response(false) },
        contextNode: (String) -> String = { "INVALID" },
    ): SelinuxDirtySepolicyRawSnapshot = probe.inspect(
        snapshot = snapshot,
        isUserBuild = true,
        query = check,
        permissionMask = { _, _ -> 1u },
        queryClassZero = queryClassZero,
        checkContextNode = contextNode,
    )
}
