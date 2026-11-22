package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.*
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAppZygoteTimingPresentationTest {
    @Test fun `positive timing raises Danger in row and card`() {
        val model = SelinuxCardModelMapper().map(report(timingResult(157, 14, 2, 400)))
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.single().status)
        assertTrue(model.methodRows.single().detail.orEmpty().contains("not proof"))
        assertTrue(model.impactItems.any { it.status == DetectorStatus.danger() &&
            it.text.contains("App Zygote invalid-context") })
    }

    @Test fun `positive median raises Danger regardless of diagnostic block counts`() {
        val model = SelinuxCardModelMapper().map(report(timingResult(53, 9, 2, 310)))
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.single().status)
        assertTrue(model.methodRows.single().detail.orEmpty().contains("A−B=53 ns"))
        assertTrue(model.methodRows.single().detail.orEmpty().contains("9/2/5"))
        assertEquals(DetectorStatus.danger(),
            SelinuxCardModelMapper().map(report(timingResult(1, 10, 5, 271))).methodRows.single().status)
        assertEquals(DetectorStatus.danger(),
            SelinuxCardModelMapper().map(report(timingResult(1, 10, 5, 271))).status)
    }

    @Test fun `negative parent and incomplete measurements never raise danger`() {
        for (result in listOf(timingResult(-104, 2, 14, 120),
            timingResult(157, 14, 2, 400, pairs = 128))) {
            val model = SelinuxCardModelMapper().map(report(result))
            assertEquals(DetectorStatus.allClear(), model.status)
            assertTrue(model.impactItems.none { it.text.contains("App Zygote invalid-context") })
        }
        val baseline = SelinuxCardModelMapper().map(report(timingResult(0, 11, 5, 400)))
        assertEquals(DetectorStatus.allClear(), baseline.status)
        assertEquals(SelinuxAppZygoteTimingVerdict.BASELINE.label, baseline.methodRows.single().value)
        val positiveChild = timingResult(364, 15, 1, 397)
        val negativeParent = requireNotNull(positiveChild.avcLookup).let { reading ->
            withReading(positiveChild, reading.copy(parentTiming = reading.parentTiming.copy(
                medianDeltaNs = -52, positiveBlocks = 0, negativeBlocks = 16, aSlower = 100,
            )))
        }
        assertEquals(DetectorStatus.allClear(), SelinuxCardModelMapper().map(report(negativeParent)).status)
    }

    @Test fun `partial migrated samples display diagnostic values but never raise danger`() {
        val base = timingResult(52, 15, 0, 470, pairs = 511)
        val reading = requireNotNull(base.avcLookup).copy(
            collection = SelinuxAvcLookupCollection.INCONCLUSIVE, cpuMigrations = 1,
            timingMediansAvailable = true,
        )
        val updated = withReading(base, reading)
        val row = appZygoteTimingRow(updated)
        assertTrue(row.detail.orEmpty().contains("A−B=52 ns"))
        assertTrue(row.detail.orEmpty().contains("diagnostic only"))
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE, reading.timingVerdict)
        assertEquals(DetectorStatus.allClear(),
            SelinuxCardModelMapper().map(report(updated)).status)
        val missing = appZygoteTimingRow(base.copy(avcLookup = reading.copy(
            timingMediansAvailable = false, parentTiming = SelinuxParentTimingReading(),
        )))
        assertTrue(missing.detail.orEmpty().contains("A−B=N/A"))
        assertTrue(missing.detail.orEmpty().contains("Parent preload: N/A"))
    }

    @Test fun `migration-only partial sample with 90 percent A slower raises Danger`() {
        val input = timingResult(573, 15, 0, 471, pairs = 511, migrations = 1)
        val model = SelinuxCardModelMapper().map(report(input))
        assertEquals(DetectorStatus.danger(), model.status)
        assertEquals(DetectorStatus.danger(), model.methodRows.single().status)
        assertTrue(model.methodRows.single().detail.orEmpty().contains("A−B=573 ns"))
        assertTrue(model.methodRows.single().detail.orEmpty().contains("A slower=471/511"))
        assertTrue(model.methodRows.single().detail.orEmpty().contains("90% A-slower criterion"))
        val weaker = SelinuxCardModelMapper().map(report(timingResult(573, 15, 0, 459, pairs = 511, migrations = 1)))
        assertEquals(DetectorStatus.allClear(), weaker.status)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE.label, weaker.methodRows.single().value)
    }

    @Test fun `carrier startup failure is unavailable and is not a negative timing measurement`() {
        val base = timingResult(0, 0, 0, 0, pairs = 0)
        val reading = requireNotNull(base.avcLookup).copy(
            collection = SelinuxAvcLookupCollection.UNAVAILABLE,
            timingMediansAvailable = false, parentTiming = SelinuxParentTimingReading(),
            details = requireNotNull(base.avcLookup).details.copy(
                failureReason = "The dedicated SELinux carrier binding died before it answered.",
            ),
        )
        val result = base.copy(avcLookup = reading)
        val timing = appZygoteTimingRow(result)
        val avc = avcLookupRow(result)
        assertTrue(timing.detail.orEmpty().contains("Collection failed: The dedicated SELinux carrier binding died"))
        assertTrue(timing.detail.orEmpty().contains("not a negative detection"))
        assertTrue(timing.detail.orEmpty().contains("A−B=N/A"))
        assertTrue(avc.detail.orEmpty().contains("not a negative detection"))
        assertEquals(SelinuxAppZygoteTimingVerdict.UNAVAILABLE, reading.timingVerdict)
        assertEquals(DetectorStatus.allClear(), SelinuxCardModelMapper().map(report(result)).status)
    }

    private fun timingResult(
        delta: Long, positive: Int, negative: Int, slower: Int,
        pairs: Int = 512, migrations: Int = 0,
    ): SelinuxCheckResult {
        val reading = SelinuxAvcLookupReading(
            collection = SelinuxAvcLookupCollection.TIMING_ONLY, writesPerBatch = 4096,
            batchesA = emptyList(), batchesB = emptyList(), completedRounds = 0,
            pairs = pairs, medianANs = 1000, medianBNs = 900, medianDeltaNs = delta,
            positiveBlocks = positive, negativeBlocks = negative, aSlower = slower,
            parentTiming = SelinuxParentTimingReading(
                attempted = true, complete = pairs == 512 && migrations == 0,
                error = if (migrations > 0) 11 else 0, pid = 12345, cpu = 7,
                pairs = pairs, migrations = migrations, aSlower = slower, medianANs = 1000, medianBNs = 900,
                medianDeltaNs = delta, protocol = 1,
                positiveBlocks = positive, negativeBlocks = negative,
                zeroBlocks = maxOf(0, pairs / 32 - positive - negative),
            ),
            details = SelinuxAvcLookupCollectionDetails(null, 2, null, false, "EXITED", 0, 0, 0,
                3, -1, 0, 0, "No cache_stats"),
        )
        return SelinuxCheckResult(
            method = SelinuxOracle.APP_ZYGOTE_ATTR_TIMING.label,
            status = reading.timingVerdict.label,
            isSecure = null,
            permissionDenied = false, oracle = SelinuxOracle.APP_ZYGOTE_ATTR_TIMING, avcLookup = reading,
        )
    }

    private fun report(method: SelinuxCheckResult) = SelinuxReport(
        stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING,
        resolvedStatusLabel = "Enforcing", filesystemMounted = true, paradoxDetected = false,
        methods = listOf(method), processContext = null, contextType = null, policyAnalysis = null,
        auditIntegrity = null, androidVersion = "14", apiLevel = 34,
    )

    private fun withReading(base: SelinuxCheckResult, reading: SelinuxAvcLookupReading) = base.copy(
        avcLookup = reading,
        status = reading.timingVerdict.label,
        isSecure = null,
    )
}
