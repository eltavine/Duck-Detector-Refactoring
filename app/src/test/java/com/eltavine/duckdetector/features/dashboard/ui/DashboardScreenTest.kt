package com.eltavine.duckdetector.features.dashboard.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class DashboardScreenTest {

    @Test
    fun `export filename sanitizes model and uses deterministic timestamp`() {
        assertEquals(
            "duck_detector_report_Pixel_7_20240102_030405.txt",
            generateExportReportFileName(" Pixel 7 ", 1704164645000L),
        )
    }

    @Test
    fun `blank model falls back to unknown`() {
        assertEquals(
            "duck_detector_report_unknown_20240102_030405.txt",
            generateExportReportFileName("   ", 1704164645000L),
        )
    }
}
