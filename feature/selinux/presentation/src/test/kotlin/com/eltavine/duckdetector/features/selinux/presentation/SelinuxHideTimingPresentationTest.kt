/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxHideTimingPresentationTest {
    private fun report(candidate: Boolean): SelinuxReport = SelinuxReport(
        stage = SelinuxStage.READY,
        mode = SelinuxMode.ENFORCING,
        resolvedStatusLabel = "Enforcing",
        filesystemMounted = true,
        paradoxDetected = false,
        methods = listOf(SelinuxCheckResult(
            method = SelinuxOracle.ATTR_CURRENT_TIMING.label,
            status = if (candidate) "Timing asymmetry (experimental)" else "No reproducible asymmetry",
            isSecure = if (candidate) false else null,
            permissionDenied = false,
            oracle = SelinuxOracle.ATTR_CURRENT_TIMING,
        )),
        processContext = null, contextType = null, policyAnalysis = null,
        auditIntegrity = null, androidVersion = "14", apiLevel = 34,
    )

    @Test fun `experimental asymmetry is danger including card status`() {
        val mapped = SelinuxCardModelMapper().map(report(candidate = true))
        assertEquals(DetectorStatus.danger(), mapped.status)
        assertEquals(DetectorStatus.danger(), mapped.methodRows.single().status)
        org.junit.Assert.assertTrue(mapped.verdict.contains("attr/current timing"))
        org.junit.Assert.assertTrue(mapped.summary.contains("device-dependent"))
        org.junit.Assert.assertTrue(mapped.subtitle.contains("attr/current timing"))
        org.junit.Assert.assertTrue(mapped.impactItems.any { it.status == DetectorStatus.danger() && it.text.contains("attr/current") })
    }

    @Test fun `no asymmetry is info not a clean integrity claim`() {
        val mapped = SelinuxCardModelMapper().map(report(candidate = false))
        assertEquals(DetectorStatus.allClear(), mapped.status)
        assertEquals(DetectorStatus.info(com.eltavine.duckdetector.core.evidence.InfoKind.SUPPORT),
            mapped.methodRows.single().status)
    }
}
