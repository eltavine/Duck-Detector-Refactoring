package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtySepolicyRawStabilityTest : SelinuxDirtySepolicyRawFixture() {
    @Test
    fun `one optional failure preserves another stable allowed rule`() {
        val result = inspect(check = { source, target, clazz, permission ->
            when {
                target == "u:object_r:ksu_file:s0" -> response(true)
                source == "u:r:msd_daemon:s0" -> throw java.io.IOException("optional query unavailable")
                else -> lookup(source, target, clazz, permission)
            }
        })
        assertEquals(SelinuxDirtySepolicyRawState.PARTIAL, result.state)
        assertTrue("untrusted_app -> ksu_file read" in result.allowedRules)
        assertTrue("untrusted_app -> ksu_file read" in result.warningRules)
    }

    @Test
    fun `additional rule instability cannot produce complete collection`() {
        var reads = 0
        val result = inspect(check = { s, t, c, p ->
            if (s == "u:r:kernel:s0" && t == "u:object_r:adb_data_file:s0") response(++reads == 1)
            else lookup(s, t, c, p)
        })
        assertEquals(2, reads)
        assertEquals(SelinuxDirtySepolicyRawState.PARTIAL, result.state)
        assertEquals(false, result.stable)
    }

    @Test
    fun `all five additional rules reject inconsistent or missing repeated results`() {
        val edges = listOf(
            "u:object_r:tmpfs:s0" to "associate",
            "u:object_r:tmpfs:s0" to "open",
            "u:object_r:adb_data_file:s0" to "read",
            "u:object_r:apk_data_file:s0" to "execute",
            "u:object_r:dex2oat_exec:s0" to "execute_no_trans",
        )
        for ((target, permission) in edges) {
            for ((first, second) in listOf(
                true to false, false to true, true to null, null to null,
            )) {
                var reads = 0
                val result = inspect(check = { source, actualTarget, clazz, actualPermission ->
                    if (actualTarget == target && actualPermission == permission) {
                        val allowed = if (++reads == 1) first else second
                        if (allowed == null) throw java.io.IOException("injected I/O failure")
                        response(allowed)
                    } else lookup(source, actualTarget, clazz, actualPermission)
                })
                assertEquals(2, reads)
                assertEquals(SelinuxDirtySepolicyRawState.PARTIAL, result.state)
                if (first != second) assertEquals(false, result.stable)
            }
        }
    }

    @Test
    fun `partial transport failure keeps a trusted unrelated edge for each errno`() {
        val errors = listOf(
            java.io.IOException("read unavailable"),
            SelinuxRawAccess.TransactionFailure("write", 13, null, java.io.IOException("EACCES")),
            SelinuxRawAccess.TransactionFailure("open", 1, null, java.io.IOException("EPERM")),
        )
        for (failure in errors) {
            val result = inspect(check = { source, target, clazz, permission ->
                when {
                    target == "u:object_r:ksu_file:s0" && permission == "read" -> response(true)
                    source == "u:r:msd_daemon:s0" -> throw failure
                    else -> lookup(source, target, clazz, permission)
                }
            })
            assertEquals(SelinuxDirtySepolicyRawState.PARTIAL, result.state)
            assertTrue("untrusted_app -> ksu_file read" in result.warningRules)
        }
    }

    @Test
    fun `attr unavailable never prevents first layer context probe`() {
        var calls = 0
        val result = inspect(snapshot = carrier.copy(procAttrCurrentResults = emptyList()), contextNode = {
            if (it == "u:r:adbroot:s0") calls++
            if (it == carrier.carrierContext || it == "u:r:adbroot:s0") "VALID" else "INVALID"
        })
        assertTrue(calls > 0)
        assertEquals(11, result.contextChecks.size)
        assertTrue("u:r:adbroot:s0" in result.recognizedContexts)
    }

    @Test
    fun `status epoch is informative while enforcement and unknown deny violations are warnings`() {
        val raw = probe.inspect(
            carrier, true, ::lookup, { _, _ -> 1u },
            { _, _ -> response(false) }, { if (it == carrier.carrierContext) "VALID" else "INVALID" },
            SelinuxStatusHeader(1, 12, 1, 3, 1),
        )
        assertTrue(raw.statusWarnings.isEmpty())
        assertTrue(raw.statusEpoch.orEmpty().contains("Non-initial"))
        val warning = probe.inspect(
            carrier, true, ::lookup, { _, _ -> 1u },
            { _, _ -> response(false) }, { if (it == carrier.carrierContext) "VALID" else "INVALID" },
            SelinuxStatusHeader(1, 4, 0, 1, 0),
        )
        assertEquals(2, warning.statusWarnings.size)
    }

    @Test
    fun `class zero success survives first layer control failure`() {
        val result = inspect(
            contextNode = { "INVALID" },
            queryClassZero = { source, _ ->
                when (source) {
                    "u:r:duckdetector_context_oracle_sentinel:s0" ->
                        throw android.system.ErrnoException("write", android.system.OsConstants.EINVAL)
                    else -> response(false)
                }
            },
        )
        assertEquals(false, result.contextControlsPassed)
        assertEquals(true, result.classZeroControlsPassed)
        val xposed = result.contextChecks.single { it.context == "u:object_r:xposed_file:s0" }
        assertEquals("VALID", xposed.verdict)
        assertEquals(SelinuxRawContextSource.ACCESS_CLASS_ZERO, xposed.verifiedBy)
        assertTrue(xposed.context in result.recognizedContexts)
        assertEquals(result, SelinuxDirtySepolicyRawCodec.decode(SelinuxDirtySepolicyRawCodec.encode(result)))
    }

    @Test
    fun `controlled attr fallback is independently trusted when context control fails`() {
        val contexts = listOf(
            "u:r:ksu:s0", "u:object_r:ksu_file:s0", "u:r:magisk:s0",
            "u:object_r:magisk_file:s0", "u:object_r:lsposed_file:s0", "u:r:droidspacesd:s0",
            "u:r:msd_app:s0", "u:r:msd_daemon:s0", "u:object_r:xposed_data:s0",
            "u:r:adbroot:s0", "u:object_r:xposed_file:s0",
        )
        val rows = listOf(SelinuxProcAttrCurrentResult("Controls", "", "CONTROLS_PASSED", "ok")) +
            contexts.map { context ->
                SelinuxProcAttrCurrentResult(context, context,
                    if (context == "u:object_r:xposed_file:s0") "CONTEXT_RECOGNIZED" else "NORMAL_EINVAL", "two rounds")
            }
        val result = inspect(
            snapshot = carrier.copy(procAttrCurrentResults = rows),
            contextNode = { "INVALID" },
            queryClassZero = { source, _ ->
                if (source == "u:r:untrusted_app:s0") response(false)
                else throw android.system.ErrnoException("write", android.system.OsConstants.EINVAL)
            },
        )
        val xposed = result.contextChecks.single { it.context == "u:object_r:xposed_file:s0" }
        assertEquals(false, result.contextControlsPassed)
        assertEquals(false, result.classZeroControlsPassed)
        assertEquals(SelinuxRawContextSource.ATTR_CURRENT, xposed.verifiedBy)
        assertTrue(xposed.context in result.recognizedContexts)
    }

    @Test
    fun `context collection is partial independently of a complete raw access collection`() {
        val result = inspect(
            contextNode = { context ->
                if (context == carrier.carrierContext) "VALID" else "UNAVAILABLE:write errno=13"
            },
            queryClassZero = { source, _ ->
                if (source == "u:r:untrusted_app:s0") response(false)
                else throw android.system.ErrnoException("write", android.system.OsConstants.EINVAL)
            },
        )
        assertEquals(SelinuxDirtySepolicyRawState.COMPLETE, result.state)
        assertEquals(SelinuxRawContextCollectionState.PARTIAL, result.contextCollection)
        assertTrue(result.contextChecks.any { it.verdict == "INCONCLUSIVE" })
    }

    @Test
    fun `shared classification includes every previously excluded root framework edge`() {
        val previouslyMissing = listOf(
            "rootfs -> tmpfs associate", "kernel -> tmpfs fifo open",
            "kernel -> adb_data_file read", "zygote -> adb_data_file search",
            "shell -> su transition", "adbd -> adbroot binder",
        )
        previouslyMissing.forEach { edge ->
            assertTrue(edge, SelinuxDirtyPolicyRuleClassification.isAlertEligible(edge))
        }
        assertTrue(SelinuxDirtyPolicyRuleClassification.isAlertEligible("system_server execmem"))
        listOf("system_server -> apk_data_file execute",
            "dex2oat -> dex2oat_exec execute_no_trans").forEach { edge ->
            assertEquals(edge, false, SelinuxDirtyPolicyRuleClassification.isAlertEligible(edge))
        }
    }

    @Test
    fun `six original DirtySepolicy edges keep their alert eligibility on raw-only hits`() {
        val edges = listOf(
            "rootfs -> tmpfs associate" to { s: String, t: String, p: String ->
                s == "u:object_r:rootfs:s0" && t == "u:object_r:tmpfs:s0" && p == "associate"
            },
            "kernel -> tmpfs fifo open" to { s: String, t: String, p: String ->
                s == "u:r:kernel:s0" && t == "u:object_r:tmpfs:s0" && p == "open"
            },
            "kernel -> adb_data_file read" to { s: String, t: String, p: String ->
                s == "u:r:kernel:s0" && t == "u:object_r:adb_data_file:s0" && p == "read"
            },
            "zygote -> adb_data_file search" to { s: String, t: String, p: String ->
                s == "u:r:zygote:s0" && t == "u:object_r:adb_data_file:s0" && p == "search"
            },
            "shell -> su transition" to { s: String, t: String, p: String ->
                s == "u:r:shell:s0" && t == "u:r:su:s0" && p == "transition"
            },
            "adbd -> adbroot binder" to { s: String, t: String, p: String ->
                s == "u:r:adbd:s0" && t == "u:r:adbroot:s0" && p == "call"
            },
        )
        for ((edge, matches) in edges) {
            val result = inspect(check = { source, target, clazz, permission ->
                if (matches(source, target, permission)) response(true)
                else lookup(source, target, clazz, permission)
            })
            assertEquals(edge, SelinuxDirtySepolicyRawState.COMPLETE, result.state)
            assertTrue(edge, edge in result.allowedRules)
            assertTrue(edge, edge in result.warningRules)
        }
    }
}
