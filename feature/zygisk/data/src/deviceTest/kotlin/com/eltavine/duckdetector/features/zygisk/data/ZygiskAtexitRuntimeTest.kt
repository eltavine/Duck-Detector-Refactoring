// SPDX-License-Identifier: Apache-2.0
package com.eltavine.duckdetector.features.zygisk.data

import android.content.pm.ApplicationInfo
import android.os.Process
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.features.zygisk.data.native.ZygiskNativeBridge
import com.eltavine.duckdetector.features.zygisk.domain.ZygiskAtexitState
import java.io.File
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** The module environment is prepared outside the app; collection uses only its ordinary UID. */
@RunWith(AndroidJUnit4::class)
class ZygiskAtexitRuntimeTest {
    @Test fun tableIsReadableWithoutElevatedAppPermissions() {
        val domain = File("/proc/self/attr/current").readText().trimEnd('\u0000', '\n')
        assertTrue("uid=${Process.myUid()}", Process.myUid() >= 10000)
        assertTrue(domain, domain.startsWith("u:r:untrusted_app"))
        val environment = InstrumentationRegistry.getArguments().getString("environment") ?: "unspecified"
        val debuggable = InstrumentationRegistry.getInstrumentation().targetContext.applicationInfo.flags and
            ApplicationInfo.FLAG_DEBUGGABLE != 0
        val bridge = ZygiskNativeBridge()
        repeat(2) {
            val snapshot = bridge.collectSnapshot()
            val table = snapshot.atexitTable
            Log.i("AtexitRuntime", "$environment uid=${Process.myUid()} domain=$domain debuggable=$debuggable " +
                "dumpable=${table.dumpable} state=${table.state} " +
                "entries=${table.entries} cleared=${table.nullEntries} gaps=${table.anchoredGaps} " +
                "callbacks=${table.anonymousCallbacks} detail=${table.detail}")
            snapshot.traces.forEach { Log.i("AtexitRuntime", "${it.label}: ${it.detail}") }
            assertTrue(snapshot.available)
            assertEquals(table.detail, ZygiskAtexitState.COLLECTED, table.state)
            assertTrue(table.entries > 0)
            if (InstrumentationRegistry.getArguments().getString("expectNonDebuggable") == "true") {
                assertFalse(debuggable)
                assertEquals(0, table.dumpable)
            }
            if (InstrumentationRegistry.getArguments().getString("expectNoAtexitEvidence") == "true") {
                assertFalse(table.toString(), table.hasEvidence)
            }
            if (InstrumentationRegistry.getArguments().getString("expectAtexitEvidence") == "true") {
                assertTrue(table.toString(), table.hasEvidence)
            }
        }
    }
}
