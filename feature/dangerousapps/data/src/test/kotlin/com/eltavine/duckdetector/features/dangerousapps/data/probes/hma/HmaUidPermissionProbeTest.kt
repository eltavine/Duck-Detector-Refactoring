/*
 * Copyright 2026 Duck Apps Contributor
 * If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
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

package com.eltavine.duckdetector.features.dangerousapps.data.probes.hma

import com.eltavine.duckdetector.features.dangerousapps.domain.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.lang.reflect.InvocationTargetException
import kotlin.coroutines.cancellation.CancellationException

class HmaUidPermissionProbeTest {
    private val caller = HmaUidPermissionCaller(10042, "caller", 37, true, true)
    private val permission = HmaUidPermissionPolicy.PERMISSIONS.first()

    private open inner class Calls : HmaUidPackageCalls {
        val trace = mutableListOf<String>()
        override fun packages(uid: Int): List<String> {
            trace += "packages:$uid"
            return if (uid == caller.uid) listOf(caller.packageName) else emptyList()
        }
        override fun permission(uid: Int, permission: String): Boolean {
            trace += "permission:$uid:$permission"
            return uid == caller.uid && permission == "android.permission.INTERNET" ||
                uid == 10043 && permission == this@HmaUidPermissionProbeTest.permission
        }
    }

    private fun probe(calls: HmaUidPackageCalls, identity: HmaUidPermissionCaller = caller,
        now: () -> Long = { 0L }, budget: Long = 1, limit: Int = 16) =
        HmaUidPermissionProbe(calls, { identity }, now, budget, limit)

    @Test fun `Android 15 through 17 compare stopped UIDs with fresh caller controls`() = runTest {
        for (sdk in 35..37) {
            val calls = Calls()
            val result = probe(calls, caller.copy(sdk = sdk)).run(DangerousPackageVisibility.FULL)
            assertEquals("API $sdk", HmaCheckState.EXPERIMENTAL_ANOMALY, result.state)
            assertEquals(listOf(10043), result.uids)
            assertEquals(2, calls.trace.count { it == "packages:10043" })
            assertEquals(2, calls.trace.count { it == "permission:10043:$permission" })
            assertEquals(2, calls.trace.count { it == "packages:10042" })
        }
    }

    @Test fun `ordinary package filtering must never start the scan`() = runTest {
        val calls = Calls()
        assertEquals(HmaCheckState.PERMISSION_LIMITED, probe(calls).run(DangerousPackageVisibility.RESTRICTED).state)
        assertTrue(calls.trace.isEmpty())
    }

    @Test fun `unreviewed versions and instant permission definitions are unsupported`() = runTest {
        for (identity in listOf(caller.copy(sdk = 34), caller.copy(sdk = 38), caller.copy(nonInstantDefinitions = false))) {
            val calls = Calls()
            assertEquals(HmaCheckState.UNSUPPORTED, probe(calls, identity).run(DangerousPackageVisibility.FULL).state)
            assertTrue(calls.trace.isEmpty())
        }
    }

    @Test fun `INTERNET alone does not create a candidate`() = runTest {
        val calls = object : Calls() {
            override fun permission(uid: Int, permission: String) = permission == "android.permission.INTERNET"
        }
        val result = probe(calls).run(DangerousPackageVisibility.FULL)
        assertEquals(HmaCheckState.CONSISTENT, result.state)
        assertTrue(result.uids.isEmpty())
    }

    @Test fun `visible shared UID associations veto the candidate`() = runTest {
        val calls = object : Calls() {
            override fun packages(uid: Int) = if (uid == 10043) listOf("visible.sibling") else super.packages(uid)
        }
        assertEquals(HmaCheckState.CONSISTENT, probe(calls).run(DangerousPackageVisibility.FULL).state)
    }

    @Test fun `an association appearing during verification is inconclusive`() = runTest {
        val calls = object : Calls() {
            var reads = 0
            override fun packages(uid: Int): List<String> =
                if (uid == 10043 && ++reads > 1) listOf("installed.now") else super.packages(uid)
        }
        val result = probe(calls).run(DangerousPackageVisibility.FULL)
        assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
        assertTrue(result.uids.isEmpty())
    }

    @Test fun `permission revoked during verification is not absence`() = runTest {
        val calls = object : Calls() {
            var reads = 0
            override fun permission(uid: Int, permission: String): Boolean =
                if (uid == 10043 && permission == this@HmaUidPermissionProbeTest.permission && ++reads > 1) false
                else super.permission(uid, permission)
        }
        assertEquals(HmaCheckState.INCONCLUSIVE, probe(calls).run(DangerousPackageVisibility.FULL).state)
    }

    @Test fun `failed trailing control drops positive claims`() = runTest {
        val calls = object : Calls() {
            var reads = 0
            override fun packages(uid: Int): List<String> =
                if (uid == caller.uid && ++reads > 1) emptyList() else super.packages(uid)
        }
        val result = probe(calls).run(DangerousPackageVisibility.FULL)
        assertEquals(HmaCheckState.INCONCLUSIVE, result.state)
        assertTrue(result.uids.isEmpty())
    }

    @Test fun `permission denial and missing methods remain explicit failures`() = runTest {
        for ((cause, state) in listOf(SecurityException() to HmaCheckState.PERMISSION_LIMITED,
            NoSuchMethodException() to HmaCheckState.UNAVAILABLE)) {
            val calls = object : Calls() {
                override fun permission(uid: Int, permission: String): Boolean {
                    if (uid != caller.uid) throw InvocationTargetException(cause)
                    return super.permission(uid, permission)
                }
            }
            assertEquals(state, probe(calls).run(DangerousPackageVisibility.FULL).state)
        }
    }

    @Test fun `a budget exhausted before the first UID stays partial`() = runTest {
        assertEquals(HmaCheckState.PARTIAL, probe(Calls(), budget = 0).run(DangerousPackageVisibility.FULL).state)
    }

    @Test fun `the candidate cap preserves verified hits and bounded coverage`() = runTest {
        val calls = object : Calls() {
            override fun permission(uid: Int, permission: String): Boolean =
                uid == 10044 && permission == this@HmaUidPermissionProbeTest.permission || super.permission(uid, permission)
        }
        val result = probe(calls, limit = 1).run(DangerousPackageVisibility.FULL)
        assertEquals(listOf(10043), result.uids)
        assertTrue(result.detail.contains("44/10000"))
        assertTrue(result.detail.contains("candidate limit reached=true"))
    }

    @Test fun `wrapped cancellation escapes the probe`() = runTest {
        val calls = object : Calls() {
            override fun packages(uid: Int): List<String> = throw InvocationTargetException(InvocationTargetException(CancellationException("cancelled")))
        }
        try {
            probe(calls).run(DangerousPackageVisibility.FULL)
            fail("Cancellation was swallowed")
        } catch (_: CancellationException) { }
    }
}
