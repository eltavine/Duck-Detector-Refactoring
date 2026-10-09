/*
 * Copyright 2026 Duck Apps Contributor
 * Licensed under the Apache License, Version 2.0.
 */

package com.eltavine.duckdetector.features.heapresidue.data.hprof

import com.eltavine.duckdetector.features.heapresidue.domain.HeapResidueArgument
import java.io.ByteArrayInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Issue #363 controls exercise the existing scanner, not proposed production rules.
 * Binary fixtures cannot establish zygote provenance or real-device visibility.
 */
class NiceNameResearchBoundaryTest {
    private val defaultPackage = "me.weishu.kernelsu"
    private val renamedPackage = "com.example.renamed"

    @Test fun applicationIdOnlyRenameLosesExistingExactPackageMatch() {
        for (idSize in listOf(4, 8)) for (wide in listOf(false, true)) {
            val original = scan("--nice-name=$defaultPackage:magica_boot", idSize, wide)
            assertEquals(defaultPackage, original.signals.single().packageName)
            assertEquals(setOf(HeapResidueArgument.NICE_NAME), original.signals.single().arguments)
            val renamed = scan("--nice-name=$renamedPackage:magica_boot", idSize, wide)
            assertTrue(renamed.signals.isEmpty())
            assertEquals(1, renamed.candidates)
        }
    }

    @Test fun recognizableServiceClassDoesNotRecoverRenamedPackage() {
        // ActiveServices puts the class in an isolated child's process name. Its presence
        // in the main zygote's inherited heap is a separate, unproven question.
        val result = scan("--nice-name=$renamedPackage:$defaultPackage.magica.MagicaService")
        assertTrue(result.signals.isEmpty())
        assertEquals(1, result.candidates)
    }

    @Test fun appZygoteNameDoesNotProvideRootFamilyIdentity() {
        // AppZygote uses a generic suffix. Even a known package plus that suffix is
        // not the exact package key the current matcher accepts.
        for (name in listOf(defaultPackage, renamedPackage, "com.example.benign")) {
            val result = scan("--nice-name=${name}_zygote")
            assertTrue(result.signals.isEmpty())
            assertEquals(1, result.candidates)
        }
    }

    @Test fun syntheticExactNameStillProducesOnlyUnauthenticatedStringEvidence() {
        // This String was created by a fixture, with no zygote request at all. Structural
        // validity is insufficient to authenticate even the existing exact-package signal.
        val result = scan("--nice-name=$defaultPackage:magica_boot")
        assertEquals(1, result.signals.size)
        assertEquals(setOf(HeapResidueArgument.NICE_NAME), result.signals.single().arguments)
    }

    @Test fun detachedArrayCannotSubstituteForJavaStringControl() {
        val bytes = HprofFixture().string("--nice-name=$defaultPackage:magica_boot", linked = false).finish()
        val result = ArtHprofScanner(setOf(defaultPackage)).scan(ByteArrayInputStream(bytes))
        assertTrue(result.signals.isEmpty())
        assertEquals(0, result.candidates)
    }

    private fun scan(value: String, idSize: Int = 4, wide: Boolean = false): HprofScan {
        val bytes = HprofFixture(idSize).string(value, wide).finish()
        return ArtHprofScanner(setOf(defaultPackage)).scan(ByteArrayInputStream(bytes))
    }
}
