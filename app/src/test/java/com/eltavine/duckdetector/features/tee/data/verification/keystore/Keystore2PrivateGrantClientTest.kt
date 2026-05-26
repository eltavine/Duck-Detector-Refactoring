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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Keystore2PrivateGrantClientTest {

    @Test
    fun `fallback constants preserve AOSP grant contract`() {
        val constants = buildDefaultKeystore2PrivateGrantConstants()

        assertEquals(0, constants.domainApp)
        assertEquals(1, constants.domainGrant)
        assertEquals(0x100, constants.permissionUse)
        assertEquals(0x4, constants.permissionGetInfo)
        assertEquals(0x104, constants.grantAccessVector)
        assertEquals(0x100, constants.permissionUse)
        assertEquals(2, constants.transactionGetKeyEntry)
        assertEquals(7, constants.transactionGrant)
        assertEquals(8, constants.transactionUngrant)
    }

    @Test
    fun `descriptor specs distinguish APP alias and GRANT namespace`() {
        val app = Keystore2PrivateGrantDescriptorSpec.app("duck_alias")
        val grant = Keystore2PrivateGrantDescriptorSpec.grant(42L)

        assertEquals(Keystore2PrivateGrantClient.DOMAIN_APP_FALLBACK, app.domain)
        assertEquals(-1L, app.nspace)
        assertEquals("duck_alias", app.alias)

        assertEquals(Keystore2PrivateGrantClient.DOMAIN_GRANT_FALLBACK, grant.domain)
        assertEquals(42L, grant.nspace)
        assertEquals(null, grant.alias)
    }

    @Test
    fun `grant namespace is an unsigned 64 bit id and may look negative`() {
        val grantId = -1L
        val grant = Keystore2PrivateGrantDescriptorSpec.grant(grantId)

        assertEquals(Keystore2PrivateGrantClient.DOMAIN_GRANT_FALLBACK, grant.domain)
        assertEquals(grantId, grant.nspace)
        assertEquals("18446744073709551615", java.lang.Long.toUnsignedString(grant.nspace))
    }

    @Test
    fun `failure classifier recognizes key not found from service code and message`() {
        assertEquals(
            Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND,
            classifyKeystore2PrivateGrantFailure(
                throwableClassName = "android.os.ServiceSpecificException",
                message = "not found",
                serviceSpecificErrorCode = Keystore2PrivateGrantClient.RESPONSE_CODE_KEY_NOT_FOUND,
            ),
        )

        assertEquals(
            Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND,
            classifyKeystore2PrivateGrantFailure(
                throwableClassName = "java.lang.IllegalStateException",
                message = "No key found by the given alias",
                serviceSpecificErrorCode = null,
            ),
        )
    }

    @Test
    fun `failure classifier separates permission and hidden api failures`() {
        assertEquals(
            Keystore2PrivateGrantErrorKind.PERMISSION_DENIED,
            classifyKeystore2PrivateGrantFailure(
                throwableClassName = "android.os.ServiceSpecificException",
                message = null,
                serviceSpecificErrorCode = Keystore2PrivateGrantClient.RESPONSE_CODE_PERMISSION_DENIED,
            ),
        )

        assertEquals(
            Keystore2PrivateGrantErrorKind.HIDDEN_API_FAILURE,
            classifyKeystore2PrivateGrantFailure(
                throwableClassName = "java.lang.ClassNotFoundException",
                message = "android.system.keystore2.IKeystoreService",
                serviceSpecificErrorCode = null,
            ),
        )
    }

    @Test
    fun `certificate blob chain keeps leaf first before parsed remaining chain`() {
        val leaf = "leaf".toByteArray()
        val chain = chainFromCertificateBlobs(
            leaf = leaf,
            remainingChain = ByteArray(0),
        )

        assertEquals(1, chain.certificates.size)
        assertEquals(leaf.size, chain.certificates.first().derLength)
        assertEquals(GrantDomainCertificateFingerprint.fromDer(leaf), chain.certificates.first())
    }

    @Test
    fun `unavailable result carries phase and detail`() {
        val result = Keystore2PrivateGrantResult.unavailable(
            phase = Keystore2PrivateGrantPhase.PRIVATE_GRANT,
            errorKind = Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND,
            detail = "private grant failed: key missing",
        )

        assertTrue(!result.available)
        assertEquals(Keystore2PrivateGrantPhase.PRIVATE_GRANT, result.phase)
        assertEquals(Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND, result.errorKind)
        assertTrue(result.detail.contains("private grant failed"))
    }

    @Test
    fun `ungrant failure kind is part of the public result vocabulary`() {
        val result = Keystore2PrivateGrantResult.unavailable(
            phase = Keystore2PrivateGrantPhase.PRIVATE_UNGRANT,
            errorKind = Keystore2PrivateGrantErrorKind.UNGRANT_FAILED,
            detail = "private ungrant failed: transient service unavailable",
        )

        assertEquals(Keystore2PrivateGrantPhase.PRIVATE_UNGRANT, result.phase)
        assertEquals(Keystore2PrivateGrantErrorKind.UNGRANT_FAILED, result.errorKind)
    }

    @Test
    fun `owner replay phase is distinct from certificate chain readback`() {
        val result = Keystore2PrivateGrantResult.unavailable(
            phase = Keystore2PrivateGrantPhase.PRIVATE_OWNER_REPLAY_GRANT,
            errorKind = Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND,
            detail = "private owner replay getKeyEntry(GRANT) failed: KEY_NOT_FOUND",
        )

        assertEquals(Keystore2PrivateGrantPhase.PRIVATE_OWNER_REPLAY_GRANT, result.phase)
        assertEquals(Keystore2PrivateGrantErrorKind.KEY_NOT_FOUND, result.errorKind)
    }
}
