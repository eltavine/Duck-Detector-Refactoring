package com.eltavine.duckdetector.capability.selinuxpolicy.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxDirtySepolicyRawProbeTest : SelinuxDirtySepolicyRawFixture() {
    @Test
    fun `replays the existing full rule plan including original DirtySepolicy self checks`() {
        val result = inspect()
        assertEquals(SelinuxDirtySepolicyRawState.COMPLETE, result.state)
        assertTrue(result.controlsPassed)
        assertTrue(result.stable)
        assertTrue(result.observations.size >= 45)
        assertEquals("u:r:app_zygote:s0 -> u:r:app_zygote:s0:process setcurrent", result.observations.first().query)
        assertEquals(2, result.observations.count { "kernel:s0" in it.query && "check_context" in it.query })
        assertTrue(result.observations.any { "rootfs:s0" in it.query && "associate" in it.query })
        assertTrue(result.observations.any { "dex2oat_exec:s0" in it.query && "execute_no_trans" in it.query })
    }

    @Test
    fun `four-field response at first DirtySepolicy self check becomes warning signal`() {
        val raw = "10000 ffffffff 0 ffffff"
        val result = inspect(check = { s, t, c, p ->
            if (p == "setcurrent") raw else lookup(s, t, c, p)
        })
        assertEquals(SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT, result.state)
        assertEquals("u:r:app_zygote:s0 -> u:r:app_zygote:s0:process setcurrent", result.failedQuery)
        assertEquals(raw, result.rawResponse)
        assertTrue(result.observations.count { it.outcome == "INVALID_ACCESS_RESULT" } >= 2)
    }

    @Test
    fun `malformed response from a later rule also becomes warning signal`() {
        val raw = "10000 ffffffff 0 ffffff"
        val result = inspect(check = { s, t, c, p ->
            if (s == "u:r:kernel:s0" && t == "u:object_r:adb_data_file:s0" && p == "read") {
                raw
            } else {
                lookup(s, t, c, p)
            }
        })
        assertEquals(SelinuxDirtySepolicyRawState.INVALID_ACCESS_RESULT, result.state)
        assertTrue(result.failedQuery.orEmpty().contains("adb_data_file"))
    }

    @Test
    fun `a changing permission result fails the existing repeated query stability gate`() {
        var execmemReads = 0
        val result = inspect(check = { s, t, c, p ->
            if (s == "u:r:system_server:s0" && p == "execmem") {
                execmemReads++
                response(execmemReads == 2)
            } else {
                lookup(s, t, c, p)
            }
        })
        assertEquals(SelinuxDirtySepolicyRawState.PARTIAL, result.state)
        assertEquals(false, result.stable)
    }

    @Test
    fun `valid six-field formatting and seqno are parsed`() {
        listOf("", "1 2 3 4 5", "1 2 3 4 nan 0", "1 2 3 4 1 xyz", "1 2 3 4 5 6 ").forEach {
            assertNull(SelinuxRawAccess.parse(it))
        }
        assertEquals(0x10000u, SelinuxRawAccess.parse("10000 ffffffff 0 ffffffff 1 0")!!.allowed)
        assertEquals(4294967295L, SelinuxRawAccess.parse("0 ffffffff 0 ffffffff 4294967295 0")!!.seqno)
        assertNull(SelinuxRawAccess.parse("0 ffffffff 0 ffffffff 4294967296 0"))
    }

    @Test
    fun `missing carrier and inaccessible access do not become dirty policy hits`() {
        assertEquals(SelinuxDirtySepolicyRawState.UNTRUSTED, inspect(snapshot = SelinuxContextValiditySnapshot(), check = { _, _, _, _ -> error("called") }).state)
        val unavailable = inspect(check = { _, _, _, _ -> error("EACCES") })
        assertEquals(SelinuxDirtySepolicyRawState.UNTRUSTED, unavailable.state)
        assertTrue(unavailable.observations.any { it.outcome == "UNAVAILABLE" })
    }

    @Test
    fun `full records survive preload serialization`() {
        val raw = inspect()
        val payload = SelinuxContextValidityPayloadCodec.encode(carrier.copy(dirtySepolicyRaw = raw))
        assertEquals(raw, SelinuxContextValidityBridge().parse(payload).dirtySepolicyRaw)
    }

    @Test
    fun `additional Native and Java rule maps round trip`() {
        val snapshot = SelinuxContextValiditySnapshot(
            dirtyPolicyAdditionalRules = mapOf("kernel -> adb_data_file read" to true),
            javaDirtyPolicyAdditionalRules = mapOf("rootfs -> tmpfs associate" to false),
        )
        val encoded = SelinuxContextValidityPayloadCodec.encode(snapshot)
        val decoded = SelinuxContextValidityBridge().parse(encoded)
        assertEquals(snapshot.dirtyPolicyAdditionalRules, decoded.dirtyPolicyAdditionalRules)
        assertEquals(snapshot.javaDirtyPolicyAdditionalRules, decoded.javaDirtyPolicyAdditionalRules)
    }

    @Test
    fun `context to access to controlled attr fallback reuses existing child results`() {
        val contexts = listOf(
            "u:r:ksu:s0", "u:object_r:ksu_file:s0", "u:r:magisk:s0",
            "u:object_r:magisk_file:s0", "u:object_r:lsposed_file:s0", "u:r:droidspacesd:s0",
            "u:r:msd_app:s0", "u:r:msd_daemon:s0", "u:object_r:xposed_data:s0",
            "u:r:adbroot:s0", "u:object_r:xposed_file:s0",
        )
        val results = listOf(
            SelinuxProcAttrCurrentResult("Controls", "", "CONTROLS_PASSED", "controls OK"),
        ) + contexts.mapIndexed { index, context ->
            SelinuxProcAttrCurrentResult(
                "target-$index", context,
                if (context == "u:object_r:xposed_file:s0") "CONTEXT_RECOGNIZED" else "NORMAL_EINVAL",
                "two rounds",
            )
        }
        val snapshot = carrier.copy(procAttrCurrentResults = results)
        val probeResult = inspect(
            snapshot = snapshot,
            queryClassZero = { source, _ ->
                if (source == "u:r:untrusted_app:s0") "0 ffffffff 0 ffffffff 9 0"
                else throw android.system.ErrnoException("access", android.system.OsConstants.EINVAL)
            },
        )
        assertEquals(9L, probeResult.avdSeqno)
        assertEquals(SelinuxDirtySepolicyRawState.COMPLETE, probeResult.state)
        assertEquals(11, probeResult.contextChecks.size)
        val file = probeResult.contextChecks.single { it.context == "u:object_r:xposed_file:s0" }
        assertEquals("INVALID", file.contextNode)
        assertEquals("INVALID", file.accessNode)
        assertEquals("CONTEXT_RECOGNIZED", file.attrCurrent)
        assertEquals("VALID", file.verdict)
        val payload = SelinuxContextValidityPayloadCodec.encode(snapshot.copy(dirtySepolicyRaw = probeResult))
        assertEquals(probeResult, SelinuxContextValidityBridge().parse(payload).dirtySepolicyRaw)
    }

    @Test
    fun `context fallback does not trust incomplete attr controls`() {
        val snapshot = carrier.copy(procAttrCurrentResults = listOf(
            SelinuxProcAttrCurrentResult("Controls", "", "CONTROLS_PASSED", "incomplete"),
            SelinuxProcAttrCurrentResult("Xposed file", "u:object_r:xposed_file:s0", "CONTEXT_RECOGNIZED", "one target"),
        ))
        val result = inspect(
            snapshot = snapshot,
            queryClassZero = { _, _ -> throw android.system.ErrnoException("access", android.system.OsConstants.EINVAL) },
        )
        val checked = result.contextChecks.single { it.context == "u:object_r:xposed_file:s0" }
        assertEquals("INCONCLUSIVE", checked.verdict)
        assertEquals("UNTRUSTED", checked.attrCurrent)
    }

    @Test
    fun `context hit requires repeated positive and negative controls`() {
        val snapshot = carrier.copy(procAttrCurrentResults = listOf(
            SelinuxProcAttrCurrentResult("Controls", "", "UNAVAILABLE", "not usable"),
            SelinuxProcAttrCurrentResult("Xposed file", "u:object_r:xposed_file:s0", "INCONCLUSIVE", "no controlled attr"),
        ))
        val contextNode: (String) -> String = { context -> when (context) {
            snapshot.carrierContext -> "VALID"
            "u:r:duckdetector_context_oracle_sentinel:s0" -> "INVALID"
            "u:object_r:xposed_file:s0" -> "VALID"
            else -> "INVALID"
        } }
        val valid = inspect(snapshot = snapshot, contextNode = contextNode)
        assertEquals(true, valid.contextControlsPassed)
        assertEquals(listOf("u:object_r:xposed_file:s0"), valid.recognizedContexts)
        assertEquals(valid, SelinuxDirtySepolicyRawCodec.decode(SelinuxDirtySepolicyRawCodec.encode(valid)))
        val invalid = inspect(snapshot = snapshot, contextNode = { "VALID" })
        assertEquals(false, invalid.contextControlsPassed)
        assertTrue(invalid.recognizedContexts.isEmpty())
    }

    @Test
    fun `trusted raw rule allow is retained even when system Java API denies it`() {
        val snapshot = carrier.copy(
            javaDirtyPolicyAvailable = true,
            javaDirtyPolicyProbeAttempted = true,
            javaDirtyPolicyCarrierMatchesExpected = true,
            javaDirtyPolicyControlsPassed = true,
            javaDirtyPolicyStable = true,
            javaDirtyPolicyAccessControlAllowed = true,
            javaDirtyPolicyNegativeControlRejected = true,
            javaDirtyPolicyKsuFileReadAllowed = false,
        )
        val result = inspect(snapshot, check = { source, target, clazz, perm ->
            if (source == "u:r:untrusted_app:s0" && target == "u:object_r:ksu_file:s0" && perm == "read") {
                response(true)
            } else {
                lookup(source, target, clazz, perm)
            }
        })
        assertEquals(SelinuxDirtySepolicyRawState.COMPLETE, result.state)
        assertTrue("untrusted_app -> ksu_file read" in result.allowedRules)
        assertTrue("untrusted_app -> ksu_file read" in result.warningRules)
        assertTrue("untrusted_app -> ksu_file read" in result.apiDisagreements)
        val encoded = SelinuxDirtySepolicyRawCodec.encode(result)
        assertEquals(result, SelinuxDirtySepolicyRawCodec.decode(encoded))
    }

    @Test
    fun `preexisting execmem remains alert eligible while new APK edge stays informational`() {
        val result = inspect(check = { source, target, clazz, permission ->
            if (source == "u:r:system_server:s0" &&
                (permission == "execmem" || target == "u:object_r:apk_data_file:s0")) {
                response(true)
            } else lookup(source, target, clazz, permission)
        })
        assertEquals(SelinuxDirtySepolicyRawState.COMPLETE, result.state)
        assertTrue("system_server execmem" in result.allowedRules)
        assertTrue("system_server -> apk_data_file execute" in result.allowedRules)
        assertTrue("system_server execmem" in result.warningRules)
        assertTrue("system_server -> apk_data_file execute" !in result.warningRules)
    }
}
