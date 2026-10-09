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

package com.eltavine.duckdetector.features.heapresidue.data.hprof

import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueArgument
import java.io.ByteArrayInputStream
import java.io.FilterInputStream
import java.io.IOException
import kotlin.random.Random
import org.junit.Assert.*
import org.junit.Test

class ArtHprofScannerTest {
    private val target = "com.target.app"
    private fun scan(bytes: ByteArray, max: Long = 64L * 1024 * 1024) =
        ArtHprofScanner(setOf(target), max).scan(ByteArrayInputStream(bytes))

    @Test fun compressedAndWideStringsWithFourAndEightByteIds() {
        for (idSize in listOf(4, 8)) for (wide in listOf(false, true)) {
            val bytes = HprofFixture(idSize).string("--package-name=$target", wide)
                .string("--nice-name=$target:worker", wide).string("--app-data-dir=/data/user/10/$target", wide).finish()
            val result = scan(bytes)
            assertEquals(bytes.size.toLong(), result.bytesRead)
            assertEquals(3, result.candidates)
            assertEquals(HeapResidueArgument.entries.toSet(), result.signals.single().arguments)
        }
    }
    @Test fun arbitraryArraysAndMetadataAreNotStringEvidence() {
        val result = scan(HprofFixture().metadata("--package-name=$target")
            .string("--package-name=$target", linked = false).finish())
        assertTrue(result.signals.isEmpty()); assertEquals(0, result.candidates)
    }
    @Test fun android17ClockRecordAfterTheHeaderIsSkipped() {
        for (idSize in listOf(4, 8)) {
            val bytes = HprofFixture(idSize, artClock = true).string("--package-name=$target").finish()
            val result = scan(bytes)
            assertEquals(target, result.signals.single().packageName)
            assertEquals(bytes.size.toLong(), result.bytesRead)
        }
    }
    @Test fun stringInstanceCanPrecedeItsClassDump() {
        val result = scan(HprofFixture(classFirst = false).string("--package-name=$target").finish())
        assertEquals(target, result.signals.single().packageName)
    }
    @Test fun unrecognizedStringLayoutFailsEvenIfEarlierStringsMatched() {
        expectFailure { scan(HprofFixture(classFirst = false, fieldBytes = 12).string("--package-name=$target").finish()) }
    }
    @Test fun mismatchedValueObjectIdIsRejected() {
        assertTrue(scan(HprofFixture().string("--package-name=$target", wrongId = true).finish()).signals.isEmpty())
    }
    @Test fun exactNamesAndArgumentBoundaries() {
        val fixture = HprofFixture()
        listOf("--package-name=$target.extra", "prefix--package-name=$target", "--package-name=$target ",
            "--nice-name=$target:", "--nice-name=$target:/evil", "--app-data-dir=/data/user/x/$target",
            "--app-data-dir=/data/user/0/$target/files", "--app-data-dir=/data/user/999999999999/$target", "--package-name=com..target.app").forEach { fixture.string(it) }
        assertTrue(scan(fixture.finish()).signals.isEmpty())
    }
    @Test fun validDataPathsAndDuplicates() {
        val bytes = HprofFixture().string("--app-data-dir=/data/data/$target")
            .string("--app-data-dir=/data/user_de/0/$target").string("--package-name=$target")
            .string("--package-name=$target").finish()
        assertEquals(1, scan(bytes).signals.size)
        assertEquals(4, scan(bytes).candidates)
    }
    @Test fun oneByteReadsAndSkipReturningZero() {
        val bytes = HprofFixture().string("--package-name=$target", true).finish()
        val source = object : FilterInputStream(ByteArrayInputStream(bytes)) {
            override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(len, 1))
            override fun skip(n: Long): Long = 0
        }
        assertEquals(target, ArtHprofScanner(setOf(target)).scan(source).signals.single().packageName)
    }
    @Test fun everyTruncationFailsInsteadOfBecomingNegative() {
        val bytes = HprofFixture().string("--package-name=$target").finish()
        for (length in 0 until bytes.size) expectFailure { scan(bytes.copyOf(length)) }
    }
    @Test fun missingEndUnknownTagOversizedRecordAndTrailingDataFail() {
        expectFailure { scan(HprofFixture().finish(false)) }
        expectFailure { scan(HprofFixture().unknownHeapTag().finish()) }
        val bytes = HprofFixture().finish()
        expectFailure { scan(bytes, bytes.size.toLong() - 1) }
        expectFailure { scan(bytes + byteArrayOf(0)) }
        val malicious = bytes.copyOf().apply { fill(0x7f, 36, 40) }
        expectFailure { scan(malicious) }
    }
    @Test fun randomMalformedInputsStayBounded() {
        val random = Random(360)
        repeat(500) {
            val bytes = random.nextBytes(random.nextInt(0, 512))
            expectFailure { scan(bytes, 1024) }
        }
    }
    @Test fun largeIrrelevantStringIsSkipped() {
        val result = scan(HprofFixture().string("x".repeat(100_000)).string("--package-name=$target").finish())
        assertEquals(target, result.signals.single().packageName)
    }
    @Test fun hostArgumentsAreNeitherCandidatesNorMatches() {
        val host = "com.host.app"
        val own = HprofFixture().string("--package-name=$host").string("--nice-name=$host:heap_residue")
            .string("--app-data-dir=/data/user/0/$host").finish()
        val result = ArtHprofScanner(setOf(target, host), host = host).scan(ByteArrayInputStream(own))
        assertTrue(result.signals.isEmpty()); assertEquals(0, result.candidates)
        val mixed = HprofFixture().string("--package-name=$host").string("--package-name=com.other.app").finish()
        assertEquals(1, ArtHprofScanner(setOf(target), host = host).scan(ByteArrayInputStream(mixed)).candidates)
    }
    @Test fun randomBlockBoundariesAndZeroLengthReadsMatchWholeReads() {
        val bytes = HprofFixture(8, classFirst = false).objects(300).string("--package-name=$target", true)
            .string("--nice-name=$target:worker").string("x".repeat(70_000))
            .string("--app-data-dir=/data/user/0/$target").finish()
        val expected = scan(bytes)
        assertEquals(HeapResidueArgument.entries.toSet(), expected.signals.single().arguments)
        val random = Random(361)
        repeat(20) {
            val source = object : FilterInputStream(ByteArrayInputStream(bytes)) {
                override fun read(b: ByteArray, off: Int, len: Int): Int =
                    if (random.nextInt(4) == 0) 0 else super.read(b, off, minOf(len, random.nextInt(1, 9)))
            }
            assertEquals(expected, ArtHprofScanner(setOf(target)).scan(source))
        }
    }
    @Test fun sourceNeverSuppliesMoreThanOneByteBeyondTheBudget() {
        val bytes = HprofFixture().objects(2_000).string("--package-name=$target").finish()
        val max = 50_000L
        var supplied = 0L
        val source = object : FilterInputStream(ByteArrayInputStream(bytes)) {
            override fun read(): Int = super.read().also { if (it >= 0) supplied++ }
            override fun read(b: ByteArray, off: Int, len: Int): Int =
                super.read(b, off, len).also { if (it > 0) supplied += it }
        }
        assertTrue(bytes.size > 2 * max)
        expectFailure { ArtHprofScanner(setOf(target), max).scan(source) }
        assertTrue("Supplied $supplied bytes", supplied <= max + 1)
    }
    private fun expectFailure(block: () -> Unit) {
        try { block(); fail("Malformed heap accepted") } catch (_: IOException) { }
    }
}
