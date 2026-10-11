package com.eltavine.duckdetector.features.selinux.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxAppZygoteTimingVerdictTest {
    private fun reading(
        delta: Long, positive: Int, negative: Int, slower: Int,
        pairs: Int = 512, migrations: Int = 0,
        collection: SelinuxAvcLookupCollection = SelinuxAvcLookupCollection.COLLECTED,
    ) = SelinuxAvcLookupReading(
        collection = collection, writesPerBatch = 4096, batchesA = emptyList(), batchesB = emptyList(),
        completedRounds = 4, pairs = pairs, medianANs = 1000, medianBNs = 1000,
        medianDeltaNs = delta, details = SelinuxAvcLookupCollectionDetails(
            step = "FINISHED", errno = 0, unexpectedWrite = null, identityChanged = false,
            childEnd = "EXITED", childExitStatus = 0, childSignal = 0, childErrno = 0,
            cpu = 3, cpuRow = 3, cpuRows = 8, possibleCpus = 8, failureReason = null,
        ),
        cpuMigrations = migrations, aSlower = slower, positiveBlocks = positive,
        negativeBlocks = negative, zeroBlocks = 16 - positive - negative,
        parentTiming = SelinuxParentTimingReading(
            attempted = true, complete = pairs == 512 && migrations == 0,
            pid = 9876, cpu = 7, pairs = pairs, migrations = migrations,
            aSlower = slower, medianANs = 1000, medianBNs = 900,
            medianDeltaNs = delta, protocol = 1,
            positiveBlocks = positive, negativeBlocks = negative,
            zeroBlocks = 16 - positive - negative,
        ),
    )

    @Test fun `zero is the exclusive sign boundary`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(1, 13, 3, 300).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE, reading(-1, 3, 13, 180).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE, reading(0, 16, 0, 420).timingVerdict)
    }

    @Test fun `PoC uses paired parent median not child block majority`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(157, 11, 5, 420).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(157, 14, 2, 210).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE, reading(-157, 2, 14, 100).timingVerdict)
    }

    @Test fun `legacy pairs and any migration are never positive`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE, reading(157, 13, 3, 340, pairs = 128).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE, reading(157, 13, 3, 340, migrations = 1).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.UNAVAILABLE, reading(
            157, 13, 3, 340, collection = SelinuxAvcLookupCollection.PERMISSION_LIMITED,
        ).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(
            53, 13, 3, 300, collection = SelinuxAvcLookupCollection.TIMING_ONLY,
        ).timingVerdict)
    }

    @Test fun `a positive pinned child does not override a negative PoC parent`() {
        val original = reading(364, 15, 1, 397)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE,
            original.copy(parentTiming = original.parentTiming.copy(
                medianDeltaNs = -52, positiveBlocks = 0, negativeBlocks = 16,
            )).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.UNAVAILABLE,
            original.copy(parentTiming = SelinuxParentTimingReading()).timingVerdict)
    }
}
