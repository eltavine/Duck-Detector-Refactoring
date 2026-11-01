package com.eltavine.duckdetector.features.selinux.domain

import org.junit.Assert.assertEquals
import org.junit.Test

class SelinuxAppZygoteTimingVerdictTest {
    private fun reading(
        delta: Long, positive: Int, negative: Int, slower: Int,
        pairs: Int = 512, migrations: Int = 0,
        collection: SelinuxAvcLookupCollection = SelinuxAvcLookupCollection.COLLECTED,
        error: Int = if (migrations > 0) 11 else 0,
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
            error = error, pid = 9876, cpu = 7, pairs = pairs, migrations = migrations,
            aSlower = slower, medianANs = 1000, medianBNs = 900,
            medianDeltaNs = delta, protocol = 1,
            positiveBlocks = positive, negativeBlocks = negative,
            zeroBlocks = maxOf(0, pairs / 32 - positive - negative),
        ),
    )

    @Test fun `zero is the exclusive sign boundary`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(1, 13, 3, 300).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE, reading(-1, 3, 13, 180).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.BASELINE, reading(0, 16, 0, 420).timingVerdict)
    }

    @Test fun `positive paired medians cannot be suppressed by diagnostic blocks`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(53, 9, 2, 310).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(52, 10, 0, 317).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(157, 11, 5, 420).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(1, 10, 5, 271).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(53, 7, 0, 210).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(157, 12, 4, 256).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.BASELINE, reading(0, 6, 9, 240).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE, reading(-157, 2, 14, 100).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE, reading(-157, 5, 11, 100).timingVerdict)
    }

    @Test fun `migration-only partial sample with at least 90 percent A-slower is positive`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE,
            reading(573, 15, 0, 471, pairs = 511, migrations = 1).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE,
            reading(1, 15, 0, 460, pairs = 511, migrations = 1).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE,
            reading(157, 8, 0, 231, pairs = 256, migrations = 256).timingVerdict)
    }

    @Test fun `migration-only fallback requires adequate evidence and no other failures`() {
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE, reading(157, 13, 3, 340, pairs = 128).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE, reading(157, 13, 3, 340, migrations = 1).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            reading(573, 15, 0, 459, pairs = 511, migrations = 1).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            reading(-573, 15, 0, 510, pairs = 511, migrations = 1).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            reading(573, 7, 0, 230, pairs = 255, migrations = 257).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            reading(573, 15, 0, 471, pairs = 511, migrations = 1, error = 5).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            reading(573, 15, 0, 471, pairs = 511, migrations = 0).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            reading(573, 15, 0, 471, pairs = 511, migrations = 2).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(
            157, 13, 3, 340, collection = SelinuxAvcLookupCollection.PERMISSION_LIMITED,
        ).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, reading(
            53, 13, 3, 300, collection = SelinuxAvcLookupCollection.TIMING_ONLY,
        ).timingVerdict)
    }

    @Test fun `completed parent evidence survives a later failed AVC child`() {
        val valid = reading(157, 13, 3, 340)
        val failedChild = valid.copy(
            collection = SelinuxAvcLookupCollection.INCONCLUSIVE,
            pairs = 0, timingMediansAvailable = false,
            details = valid.details.copy(childEnd = "TIMED_OUT", childSignal = 9),
        )
        assertEquals(SelinuxAppZygoteTimingVerdict.POSITIVE, failedChild.timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.INCONCLUSIVE,
            valid.copy(parentTiming = valid.parentTiming.copy(complete = false, error = 5)).timingVerdict)
    }

    @Test fun `a positive pinned child does not override a negative PoC parent`() {
        val original = reading(364, 15, 1, 397)
        assertEquals(SelinuxAppZygoteTimingVerdict.NEGATIVE,
            original.copy(parentTiming = original.parentTiming.copy(
                medianDeltaNs = -52, positiveBlocks = 0, negativeBlocks = 16, aSlower = 100,
            )).timingVerdict)
        assertEquals(SelinuxAppZygoteTimingVerdict.UNAVAILABLE,
            original.copy(parentTiming = SelinuxParentTimingReading()).timingVerdict)
    }
}
