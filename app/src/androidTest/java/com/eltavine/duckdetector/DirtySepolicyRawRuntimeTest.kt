package com.eltavine.duckdetector

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import android.util.Log
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.toDetectorStatus
import com.eltavine.duckdetector.sdk.DuckDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DirtySepolicyRawRuntimeTest {
    @Test
    fun directAccessReportMatchesWarningContract() = runBlocking(Dispatchers.IO) {
        val detector = DuckDetector.detectors.single { it.id.value == "selinux" }
        val report = detector.createScanner(InstrumentationRegistry.getInstrumentation().targetContext)
            .scan() as SelinuxReport
        val raw = report.methods.singleOrNull { it.method == SelinuxOracle.DIRTY_SEPOLICY_RAW.label }
        assertNotNull("Missing raw SELinux access method", raw)
        val result = requireNotNull(raw)
        assertTrue("No raw probe diagnostic: $result", !result.details.isNullOrBlank())
        Log.i("DirtySepolicyRawTest", "raw=${result.status} details=${result.details}")
        assertTrue("Raw access result was not collected", result.status != "Not collected")
        if (result.status in setOf("Response valid", "Allowed rules observed", "Raw/API disagreement",
                "Root contexts observed", "DirtySepolicy WARNING", "DirtySepolicy ERROR")) {
            assertTrue("Raw replay did not execute multiple queries", result.details.orEmpty().contains("distinct queries="))
            assertTrue("DirtySepolicy setcurrent self-check was omitted", result.details.orEmpty().contains("process setcurrent"))
            assertTrue("DirtySepolicy check_context self-check was omitted", result.details.orEmpty().contains("security check_context"))
        }
        if (result.details.orEmpty().contains("Access collection=COMPLETE")) {
            assertTrue("Missing upstream compatibility verdict", result.details.orEmpty().contains("DirtySepolicy 2.2 compatibility="))
            assertTrue("A complete raw access collection did not run compatibility interpretation",
                !result.details.orEmpty().contains("DirtySepolicy 2.2 compatibility=NOT_COLLECTED"))
        }
        val missingEdges = listOf(
            "rootfs -> tmpfs associate",
            "kernel -> tmpfs fifo open",
            "kernel -> adb_data_file read",
            "system_server -> apk_data_file execute",
            "dex2oat -> dex2oat_exec execute_no_trans",
        )
        missingEdges.forEach { edge ->
            val rule = report.methods.singleOrNull { it.policyRule?.edge == edge }
            assertNotNull("Missing original DirtySepolicy edge $edge", rule)
            Log.i("DirtySepolicyRawTest", "$edge=${rule!!.status}; ${rule.details}")
        }
        if (result.status == "Invalid access result") {
            assertEquals(false, result.isSecure)
            assertTrue("Missing invalid-result details", result.details!!.contains("Raw response="))
            assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
        }
    }
}
