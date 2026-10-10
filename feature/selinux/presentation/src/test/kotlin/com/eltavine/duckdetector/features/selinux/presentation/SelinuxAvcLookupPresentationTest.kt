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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupCollection
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupCollectionDetails
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupProfile
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAvcLookupReading
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxOracle
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxAvcLookupPresentationTest {
    private val one = List(4) { 4102L }
    private val two = List(4) { 8198L }
    private val quietSummary = "SELinux is enforcing and the visible policy surface looks internally consistent."

    @Test fun `an extra lookup adds one informational line and never raises the card`() {
        listOf(reading(one, two), reading(two, two)).forEach { reading ->
            val model = SelinuxCardModelMapper().map(report(reading))
            assertEquals(DetectorStatus.allClear(), model.status)
            assertEquals("Enforcing", model.verdict)
            assertEquals(quietSummary, model.summary)
            val lines = model.impactItems.filter { it.text == AVC_EXTRA_LOOKUP_IMPACT }
            assertEquals(1, lines.size)
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), lines.single().status)
            val row = model.methodRows.single()
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), row.status)
            assertEquals(reading.profile!!.label, row.value)
            assertTrue(row.detail!!.contains("not tool identification or root proof"))
        }
    }

    @Test fun `stock counts unclassified counts and coverage gaps stay in an informational row`() {
        val readings = listOf(reading(one, one), reading(one, two.dropLast(1) + 9000L)) +
            SelinuxAvcLookupCollection.entries.filter { it != SelinuxAvcLookupCollection.COLLECTED }
                .map { reading(one, two, it) }
        readings.forEach { reading ->
            val model = SelinuxCardModelMapper().map(report(reading))
            assertEquals(DetectorStatus.allClear(), model.status)
            assertEquals(quietSummary, model.summary)
            assertTrue(model.impactItems.none { it.text == AVC_EXTRA_LOOKUP_IMPACT })
            // A permission-limited reading must not fall through to the all-clear default of other probes.
            assertEquals(DetectorStatus.info(InfoKind.SUPPORT), model.methodRows.single().status)
            assertEquals(reading.label, model.methodRows.single().value)
        }
        val stock = SelinuxCardModelMapper().map(report(reading(one, one))).methodRows.single().detail!!
        assertTrue(stock.contains("not a clean result"))
        assertTrue(stock.contains("A batches=4102, 4102, 4102, 4102"))
        assertTrue(stock.contains("A rate=1.001"))
        assertTrue(stock.contains("CPU 4 is cache_stats row 2 of 4"))
        assertTrue(stock.contains("timing is not interpreted"))
    }

    @Test fun `only the typed reading decides, never the status text`() {
        val result = SelinuxCheckResult(
            method = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS.label,
            status = SelinuxAvcLookupProfile.ONE_TWO.label,
            isSecure = null,
            permissionDenied = false,
            oracle = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS,
            avcLookup = reading(one, one),
        )
        val model = SelinuxCardModelMapper().map(report(result))
        assertTrue(model.impactItems.none { it.text == AVC_EXTRA_LOOKUP_IMPACT })
        assertEquals(SelinuxAvcLookupProfile.ONE_ONE.label, model.methodRows.single().value)
    }

    private fun report(reading: SelinuxAvcLookupReading) = report(SelinuxCheckResult(
        method = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS.label, status = reading.label, isSecure = null,
        permissionDenied = reading.collection == SelinuxAvcLookupCollection.PERMISSION_LIMITED,
        oracle = SelinuxOracle.APP_ZYGOTE_AVC_LOOKUPS, avcLookup = reading,
    ))

    private fun report(result: SelinuxCheckResult) = SelinuxReport(
        stage = SelinuxStage.READY, mode = SelinuxMode.ENFORCING, resolvedStatusLabel = "Enforcing",
        filesystemMounted = true, paradoxDetected = false, methods = listOf(result),
        processContext = null, contextType = null, policyAnalysis = null, auditIntegrity = null,
        androidVersion = "15", apiLevel = 35,
    )

    private fun reading(
        a: List<Long>,
        b: List<Long>,
        collection: SelinuxAvcLookupCollection = SelinuxAvcLookupCollection.COLLECTED,
    ) = SelinuxAvcLookupReading(
        collection = collection, writesPerBatch = 4096, batchesA = a, batchesB = b, completedRounds = 4,
        pairs = 128, medianANs = 301, medianBNs = 201, medianDeltaNs = 100,
        details = SelinuxAvcLookupCollectionDetails(
            step = "FINISHED", errno = 0, unexpectedWrite = null, identityChanged = false, childEnd = "EXITED",
            childExitStatus = 0, childSignal = 0, childErrno = 0, cpu = 4, cpuRow = 2, cpuRows = 4, possibleCpus = 4,
            failureReason = null,
        ),
    )
}
