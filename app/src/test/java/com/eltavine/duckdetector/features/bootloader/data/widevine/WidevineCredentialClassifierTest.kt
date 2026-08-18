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

package com.eltavine.duckdetector.features.bootloader.data.widevine

import org.junit.Assert.assertEquals
import org.junit.Test

class WidevineCredentialClassifierTest {

    private val classifier = WidevineCredentialClassifier()
    private val lockedContext = WidevineBootContext(
        rootOfTrustUnlocked = false,
        bootStateAppearsLocked = true,
    )

    @Test
    fun `normal system id and working hardware session are clean`() {
        val assessment = classifier.classify(snapshot(systemId = "38497"), lockedContext)

        assertEquals(WidevineAssessmentSeverity.SAFE, assessment.credential().severity)
        assertEquals("Consistent", assessment.credential().value)
    }

    @Test
    fun `unrelated ten digit system id does not match sentinel`() {
        val assessment = classifier.classify(
            snapshot(systemId = "1234567890"),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.SAFE, assessment.credential().severity)
    }

    @Test
    fun `exact sentinel on locked looking boot state is warning`() {
        val assessment = classifier.classify(
            snapshot(systemId = WIDEVINE_SENTINEL_SYSTEM_ID),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.WARNING, assessment.credential().severity)
        assertEquals("Sentinel system ID", assessment.credential().value)
    }

    @Test
    fun `sentinel system id without advertised L1 does not trigger sentinel rule`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = WIDEVINE_SENTINEL_SYSTEM_ID,
                securityLevel = "L3",
                actualLevel = WidevineSessionSecurityLevel.SW_SECURE_CRYPTO,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.SAFE, assessment.credential().severity)
    }

    @Test
    fun `sentinel with independently confirmed unlock is danger`() {
        val assessment = classifier.classify(
            snapshot(systemId = WIDEVINE_SENTINEL_SYSTEM_ID),
            WidevineBootContext(
                rootOfTrustUnlocked = true,
                bootStateAppearsLocked = false,
            ),
        )

        assertEquals(WidevineAssessmentSeverity.DANGER, assessment.credential().severity)
        assertEquals("Unlock impact confirmed", assessment.credential().value)
    }

    @Test
    fun `sentinel with downgraded session is danger`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = WIDEVINE_SENTINEL_SYSTEM_ID,
                actualLevel = WidevineSessionSecurityLevel.SW_SECURE_CRYPTO,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.DANGER, assessment.credential().severity)
        assertEquals("Session downgrade", assessment.credential().value)
    }

    @Test
    fun `L1 session downgrade is danger without sentinel`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = "38497",
                actualLevel = WidevineSessionSecurityLevel.HW_SECURE_DECODE,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.DANGER, assessment.credential().severity)
    }

    @Test
    fun `non transient L1 hardware session failure is danger`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = "38497",
                sessionStatus = WidevineOperationStatus.FAILURE,
                actualLevel = null,
                keyRequestStatus = WidevineOperationStatus.NOT_ATTEMPTED,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.DANGER, assessment.credential().severity)
        assertEquals("Hardware session failed", assessment.credential().value)
    }

    @Test
    fun `sentinel with provisioning failure is danger`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = WIDEVINE_SENTINEL_SYSTEM_ID,
                credentialStatus = WidevineOperationStatus.NOT_PROVISIONED,
                credentialAvailable = null,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.DANGER, assessment.credential().severity)
        assertEquals("Invalid credential", assessment.credential().value)
    }

    @Test
    fun `sentinel with non transient local key request failure is danger`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = WIDEVINE_SENTINEL_SYSTEM_ID,
                keyRequestStatus = WidevineOperationStatus.FAILURE,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.DANGER, assessment.credential().severity)
        assertEquals("Invalid credential", assessment.credential().value)
    }

    @Test
    fun `resource busy hardware session is support only`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = "38497",
                sessionStatus = WidevineOperationStatus.RESOURCE_BUSY,
                actualLevel = null,
                keyRequestStatus = WidevineOperationStatus.NOT_ATTEMPTED,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.SUPPORT, assessment.credential().severity)
        assertEquals("Inconclusive", assessment.credential().value)
    }

    @Test
    fun `missing credential without sentinel is partial rather than clean or danger`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = "38497",
                credentialAvailable = false,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.SUPPORT, assessment.credential().severity)
        assertEquals("Partial", assessment.credential().value)
    }

    @Test
    fun `Java and native system id mismatch is warning`() {
        val assessment = classifier.classify(
            snapshot(
                systemId = "38497",
                nativeSystemId = WIDEVINE_SENTINEL_SYSTEM_ID,
            ),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.WARNING, assessment.parity().severity)
        assertEquals("Mismatch", assessment.parity().value)
    }

    @Test
    fun `native unavailability only reduces coverage`() {
        val assessment = classifier.classify(
            snapshot(systemId = "38497").copy(native = WidevineNativeSnapshot()),
            lockedContext,
        )

        assertEquals(WidevineAssessmentSeverity.SUPPORT, assessment.parity().severity)
        assertEquals("Native unavailable", assessment.parity().value)
    }

    private fun snapshot(
        systemId: String,
        securityLevel: String = "L1",
        nativeSystemId: String = systemId,
        sessionStatus: WidevineOperationStatus = WidevineOperationStatus.SUCCESS,
        actualLevel: WidevineSessionSecurityLevel? = WidevineSessionSecurityLevel.HW_SECURE_ALL,
        credentialStatus: WidevineOperationStatus = WidevineOperationStatus.SUCCESS,
        credentialAvailable: Boolean? = true,
        keyRequestStatus: WidevineOperationStatus = WidevineOperationStatus.SUCCESS,
    ): WidevineCredentialSnapshot {
        return WidevineCredentialSnapshot(
            schemeSupported = true,
            javaSecurityLevel = property(securityLevel),
            javaSystemId = property(systemId),
            native = WidevineNativeSnapshot(
                available = true,
                securityLevel = property(securityLevel),
                systemId = property(nativeSystemId),
                securityLevelStatusCode = 0,
                systemIdStatusCode = 0,
            ),
            sessionStatus = sessionStatus,
            actualSessionSecurityLevel = actualLevel,
            credentialStatus = credentialStatus,
            credentialAvailable = credentialAvailable,
            keyRequestStatus = keyRequestStatus,
        )
    }

    private fun property(value: String): WidevinePropertyRead {
        return WidevinePropertyRead(WidevinePropertyStatus.AVAILABLE, value)
    }

    private fun WidevineCredentialAssessment.credential(): WidevineAssessmentFinding {
        return findings.single { it.id == "widevine_credential" }
    }

    private fun WidevineCredentialAssessment.parity(): WidevineAssessmentFinding {
        return findings.single { it.id == "widevine_property_parity" }
    }
}
