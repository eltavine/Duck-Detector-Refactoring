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

import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingGroup
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderFindingSeverity
import com.eltavine.duckdetector.features.bootloader.domain.BootloaderMethodOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WidevineCredentialRepositoryTest {

    @Test
    fun `sentinel maps to consistency warning without a bootloader state result`() {
        val repository = repository(snapshot(systemId = WIDEVINE_SENTINEL_SYSTEM_ID))

        val evidence = repository.inspect(
            WidevineBootContext(
                rootOfTrustUnlocked = false,
                bootStateAppearsLocked = true,
            ),
        )

        assertTrue(evidence.findings.all { it.group == BootloaderFindingGroup.CONSISTENCY })
        assertEquals(
            BootloaderFindingSeverity.WARNING,
            evidence.findings.single { it.id == "widevine_credential" }.severity,
        )
        assertEquals(BootloaderMethodOutcome.WARNING, evidence.method.outcome)
        assertEquals(1, evidence.anomalyCount)
        assertEquals(BootloaderFindingSeverity.WARNING, evidence.impacts.single().severity)
    }

    @Test
    fun `RootOfTrust unlock remains separate from sentinel evidence`() {
        val repository = repository(snapshot(systemId = WIDEVINE_SENTINEL_SYSTEM_ID))

        val evidence = repository.inspect(
            WidevineBootContext(
                rootOfTrustUnlocked = true,
                bootStateAppearsLocked = false,
            ),
        )

        assertEquals(
            BootloaderFindingSeverity.WARNING,
            evidence.findings.single { it.id == "widevine_credential" }.severity,
        )
        assertEquals(BootloaderMethodOutcome.WARNING, evidence.method.outcome)
    }

    @Test
    fun `corroborated Widevine anomaly maps to danger`() {
        val repository = repository(
            snapshot(
                systemId = WIDEVINE_SENTINEL_SYSTEM_ID,
                actualLevel = WidevineSessionSecurityLevel.SW_SECURE_CRYPTO,
            ),
        )

        val evidence = repository.inspect(
            WidevineBootContext(
                rootOfTrustUnlocked = false,
                bootStateAppearsLocked = true,
            ),
        )

        val credential = evidence.findings.single { it.id == "widevine_credential" }
        assertEquals(BootloaderFindingSeverity.DANGER, credential.severity)
        assertEquals(BootloaderMethodOutcome.DANGER, evidence.method.outcome)
    }

    @Test
    fun `unsupported Widevine maps to support method and no anomaly`() {
        val repository = repository(WidevineCredentialSnapshot(schemeSupported = false))

        val evidence = repository.inspect(
            WidevineBootContext(
                rootOfTrustUnlocked = false,
                bootStateAppearsLocked = true,
            ),
        )

        assertEquals(BootloaderMethodOutcome.SUPPORT, evidence.method.outcome)
        assertEquals(0, evidence.anomalyCount)
        assertTrue(evidence.impacts.isEmpty())
    }

    private fun repository(snapshot: WidevineCredentialSnapshot): WidevineCredentialRepository {
        return WidevineCredentialRepository(
            source = WidevineCredentialSource { snapshot },
        )
    }

    private fun snapshot(
        systemId: String,
        actualLevel: WidevineSessionSecurityLevel = WidevineSessionSecurityLevel.HW_SECURE_ALL,
    ): WidevineCredentialSnapshot {
        val securityLevel = WidevinePropertyRead(WidevinePropertyStatus.AVAILABLE, "L1")
        val id = WidevinePropertyRead(WidevinePropertyStatus.AVAILABLE, systemId)
        return WidevineCredentialSnapshot(
            schemeSupported = true,
            hardwareSecureAllSupported = true,
            javaSecurityLevel = securityLevel,
            javaSystemId = id,
            native = WidevineNativeSnapshot(
                available = true,
                securityLevel = securityLevel,
                systemId = id,
                securityLevelStatusCode = 0,
                systemIdStatusCode = 0,
            ),
            sessionStatus = WidevineOperationStatus.SUCCESS,
            actualSessionSecurityLevel = actualLevel,
            credentialStatus = WidevineOperationStatus.SUCCESS,
            credentialAvailable = true,
            keyRequestStatus = WidevineOperationStatus.SUCCESS,
        )
    }
}
