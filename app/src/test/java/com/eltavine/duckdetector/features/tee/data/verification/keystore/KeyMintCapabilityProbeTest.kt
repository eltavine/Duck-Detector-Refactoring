/*
 * Copyright 2026 Duck Apps Contributor
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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyMintCapabilityProbeTest {

    @Test
    fun `backend classifier keeps explicit legacy separate from keymint`() {
        assertEquals(
            KeyMintBackendFamily.LEGACY_KEYMASTER,
            classifyKeyMintBackend(
                attestationVersion = 4,
                keymasterVersion = 41,
                declaredKeyMintVersion = null,
                legacyKeymasterDeclared = true,
                runtimeIdentityConsistent = true,
            ).family,
        )
        assertEquals(
            KeyMintBackendFamily.KEYMINT,
            classifyKeyMintBackend(
                attestationVersion = 200,
                keymasterVersion = 200,
                declaredKeyMintVersion = null,
                legacyKeymasterDeclared = false,
                runtimeIdentityConsistent = true,
            ).family,
        )
    }

    @Test
    fun `backend classifier skips unknown instead of assuming keymint1`() {
        val decision = classifyKeyMintBackend(
            attestationVersion = null,
            keymasterVersion = null,
            declaredKeyMintVersion = null,
            legacyKeymasterDeclared = false,
            runtimeIdentityConsistent = true,
        )

        assertEquals(KeyMintBackendFamily.UNKNOWN, decision.family)
        assertTrue(decision.skipDetail.contains("could not be established"))
    }

    @Test
    fun `backend classifier treats mixed version families as conflict`() {
        val decision = classifyKeyMintBackend(
            attestationVersion = 300,
            keymasterVersion = 41,
            declaredKeyMintVersion = null,
            legacyKeymasterDeclared = false,
            runtimeIdentityConsistent = false,
        )

        assertEquals(KeyMintBackendFamily.CONFLICT, decision.family)
        assertTrue(decision.skipDetail.contains("runtime identity signals conflict"))
    }

    @Test
    fun `backend classifier treats unequal keymint projections as conflict`() {
        val decision = classifyKeyMintBackend(
            attestationVersion = 100,
            keymasterVersion = 300,
            declaredKeyMintVersion = 300,
            legacyKeymasterDeclared = false,
            runtimeIdentityConsistent = false,
        )

        assertEquals(KeyMintBackendFamily.CONFLICT, decision.family)
        assertTrue(decision.skipDetail.contains("runtime identity signals conflict"))
    }

    @Test
    fun `mgf1 plan skips when selected security level identity conflicts`() {
        val plan = resolveMgf1ProbePlan(
            backend = KeyMintBackendDecision(
                family = KeyMintBackendFamily.KEYMINT,
                version = 300,
                attestationVersion = 300,
                keymasterVersion = 300,
                skipDetail = "",
            ),
            securityLevelsConsistent = false,
        )

        assertEquals(Mgf1ProbeMode.SKIP, plan.mode)
        assertTrue(plan.detail.contains("security levels disagree"))
    }

    @Test
    fun `mgf1 plan uses operation only for keymint1 and keymint2`() {
        listOf(100, 200).forEach { version ->
            val plan = resolveMgf1ProbePlan(
                backend = KeyMintBackendDecision(
                    family = KeyMintBackendFamily.KEYMINT,
                    version = version,
                    attestationVersion = version,
                    keymasterVersion = version,
                    skipDetail = "",
                ),
                securityLevelsConsistent = true,
            )

            assertEquals(Mgf1ProbeMode.OPERATION_ONLY, plan.mode)
        }
    }

    @Test
    fun `mgf1 plan requires characteristics from keymint3 onward`() {
        val plan = resolveMgf1ProbePlan(
            backend = KeyMintBackendDecision(
                family = KeyMintBackendFamily.KEYMINT,
                version = 300,
                attestationVersion = 300,
                keymasterVersion = 300,
                skipDetail = "",
            ),
            securityLevelsConsistent = true,
        )

        assertEquals(Mgf1ProbeMode.CHARACTERISTICS_AND_OPERATION, plan.mode)
    }

    @Test
    fun `mgf1 plan preserves backend skip reason`() {
        val plan = resolveMgf1ProbePlan(
            backend = KeyMintBackendDecision(
                family = KeyMintBackendFamily.CONFLICT,
                version = 300,
                attestationVersion = 100,
                keymasterVersion = 300,
                skipDetail = "runtime identity conflict",
            ),
            securityLevelsConsistent = true,
        )

        assertEquals(Mgf1ProbeMode.SKIP, plan.mode)
        assertEquals("runtime identity conflict", plan.detail)
    }

    @Test
    fun `mgf1 probe runs when generated key retains hardware sha256 authorization`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x10000002, intValue = 3, securityLevel = 1),
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 1),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
        )

        assertTrue(capability.supported)
        assertTrue(capability.shouldExecute)
    }

    @Test
    fun `mgf1 probe skips legacy key characteristics`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x10000002, intValue = 3, securityLevel = 1),
                AuthorizationSummary(tag = 0x20000005, intValue = 4, securityLevel = 1),
                AuthorizationSummary(tag = 0x6000012E, intValue = null, securityLevel = 100),
            ),
            attestationVersion = 4,
            keymasterVersion = 41,
        )

        assertFalse(capability.supported)
        assertFalse(capability.shouldExecute)
        assertTrue(capability.detail.contains("legacy Keymaster/km_compat"))
    }

    @Test
    fun `keymint3 unreadable characteristics fail closed`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = emptyList(),
            attestationVersion = 300,
            keymasterVersion = 300,
        )

        assertFalse(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("omit RSA_OAEP_MGF_DIGEST"))
    }

    @Test
    fun `keymint3 missing mgf tag is failure not skip`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x10000002, intValue = 3, securityLevel = 1),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
        )

        assertFalse(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("KeyMint 3+"))
    }

    @Test
    fun `keymint2 missing mgf tag uses raw operation checks`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x10000002, intValue = 3, securityLevel = 1),
            ),
            attestationVersion = 200,
            keymasterVersion = 200,
        )

        assertTrue(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("raw keystore2"))
    }

    @Test
    fun `keymint1 missing mgf tag uses raw operation checks`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x10000002, intValue = 3, securityLevel = 1),
            ),
            attestationVersion = 100,
            keymasterVersion = 100,
        )

        assertTrue(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("raw keystore2"))
    }

    @Test
    fun `legacy keymaster missing mgf tag still skips`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x10000002, intValue = 3, securityLevel = 1),
            ),
            attestationVersion = 4,
            keymasterVersion = 41,
        )

        assertFalse(capability.supported)
        assertFalse(capability.shouldExecute)
        assertTrue(capability.detail.contains("legacy Keymaster/km_compat"))
    }

    @Test
    fun `vintf keymint2 declaration does not override conflicting legacy signals`() {
        val decision = classifyKeyMintBackend(
            attestationVersion = 4,
            keymasterVersion = 41,
            declaredKeyMintVersion = 200,
            legacyKeymasterDeclared = false,
            runtimeIdentityConsistent = false,
        )

        assertEquals(KeyMintBackendFamily.CONFLICT, decision.family)
    }

    @Test
    fun `highest observed keymint version controls strictness`() {
        assertEquals(300, deriveObservedKeyMintVersion(300, 300, 200))
        assertEquals(200, deriveObservedKeyMintVersion(200, 200, 300))
        assertEquals(200, deriveObservedKeyMintVersion(4, 41, 200))
    }

    @Test
    fun `vintf version is fallback only when runtime versions are absent`() {
        assertEquals(300, deriveObservedKeyMintVersion(null, null, 300))
        assertEquals(200, deriveObservedKeyMintVersion(200, null, 300))
    }

    @Test
    fun `wrong hardware security level mgf tag is failure`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 100),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
        )

        assertFalse(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("selected hardware security level"))
    }

    @Test
    fun `extra mgf authorization is failure`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 1),
                AuthorizationSummary(tag = 0x200000CB, intValue = 2, securityLevel = 1),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
        )

        assertFalse(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("expected=[4]"))
    }

    @Test
    fun `duplicate sha256 mgf authorization is failure`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 1),
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 1),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
        )

        assertFalse(capability.supported)
        assertTrue(capability.shouldExecute)
    }

    @Test
    fun `strongbox sha256 mgf authorization matches selected level`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 2),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
            expectedSecurityLevel = 2,
        )

        assertTrue(capability.supported)
        assertTrue(capability.shouldExecute)
    }

    @Test
    fun `keymint2 returned key security level mismatch fails`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = emptyList(),
            attestationVersion = 200,
            keymasterVersion = 200,
            expectedSecurityLevel = 2,
            returnedSecurityLevel = 1,
        )

        assertFalse(capability.supported)
        assertTrue(capability.shouldExecute)
        assertTrue(capability.detail.contains("security level=1"))
    }

    @Test
    fun `keymint3 returned key security level mismatch fails before characteristics`() {
        val capability = evaluateRsaOaepMgf1Capability(
            authorizations = listOf(
                AuthorizationSummary(tag = 0x200000CB, intValue = 4, securityLevel = 2),
            ),
            attestationVersion = 300,
            keymasterVersion = 300,
            expectedSecurityLevel = 2,
            returnedSecurityLevel = 1,
        )

        assertFalse(capability.supported)
        assertTrue(capability.detail.contains("expected=2"))
    }

    @Test
    fun `raw mgf rejection matrix matches vts cases and exact errors`() {
        val cases = keyMintMgfRejectionCases()

        assertTrue(cases.any { it.name == "default-sha1" && it.mgfDigest == null })
        assertEquals(setOf(-78, -79), cases.single { it.name == "default-sha1" }.expectedErrorCodes)
        assertEquals(3, cases.single { it.name == "explicit-sha224" }.mgfDigest)
        assertEquals(setOf(-78), cases.single { it.name == "explicit-sha224" }.expectedErrorCodes)
        assertEquals(0, cases.single { it.name == "unsupported-none" }.mgfDigest)
        assertEquals(setOf(-79), cases.single { it.name == "unsupported-none" }.expectedErrorCodes)
    }
}
