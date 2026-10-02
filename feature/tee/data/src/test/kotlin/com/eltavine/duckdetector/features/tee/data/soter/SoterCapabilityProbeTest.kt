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

package com.eltavine.duckdetector.features.tee.data.soter

import com.eltavine.duckdetector.features.tee.domain.TeeSoterAnomalyKind
import com.tencent.soter.core.SoterCore
import com.tencent.soter.core.model.SoterCoreResult
import com.tencent.soter.core.model.SoterPubKeyModel
import com.tencent.soter.soterserver.SoterSessionResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SoterCapabilityProbeTest {

    @Test
    fun `treble unreachable skips soter probe`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = false,
        )

        val state = probe(client).inspect()

        assertFalse(state.serviceReachable)
        assertFalse(state.damaged)
        assertFalse(state.available)
        assertTrue(state.summary.contains("Soter check skipped", ignoreCase = true))
        assertTrue(client.initTrebleCalled)
        assertFalse(client.generateAskCalled)
        assertFalse(client.initSighCalled)
    }

    @Test
    fun `expected simplified chinese device without soter package becomes abnormal environment`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = false,
        )

        val state = probe(
            client,
            environment = SoterEnvironmentSnapshot(
                supportExpected = true,
                simplifiedChineseLocale = true,
                servicePackageVisible = false,
                biometricAuthenticationAvailable = false,
            ),
        ).inspect()

        assertFalse(state.serviceReachable)
        assertFalse(state.damaged)
        assertTrue(state.abnormalEnvironment)
        assertTrue(state.summary.contains("abnormal soter environment", ignoreCase = true))
    }

    @Test
    fun `available biometric suppresses abnormal environment heuristic`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = false,
        )

        val state = probe(
            client,
            environment = SoterEnvironmentSnapshot(
                supportExpected = true,
                simplifiedChineseLocale = true,
                servicePackageVisible = false,
                biometricAuthenticationAvailable = true,
            ),
        ).inspect()

        assertFalse(state.abnormalEnvironment)
        assertTrue(state.summary.contains("Soter check skipped", ignoreCase = true))
    }

    @Test
    fun `pre existing ask is not removed during cleanup`() {
        val client = workingClient()

        val state = probe(client).inspect()

        assertTrue(state.available)
        assertFalse(state.damaged)
        assertTrue(state.anomalies.isEmpty())
        assertTrue(client.removeAuthCalled)
        assertFalse(client.removeAskCalled)
    }

    @Test
    fun `treble uid is set to the app uid before initialization`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = false,
        )

        probe(client).inspect()

        assertEquals(TEST_UID, client.trebleUid)
        assertTrue(client.trebleUidSetBeforeInit)
    }

    @Test
    fun `soter models captured during preparation feed reply review`() {
        val relayJson = """{"pub_key":"","cpu_id":"090000005171734c42866bea148b21f5","counter":1,"uid":"$TEST_UID"}"""
        val client = workingClient(modelJson = relayJson)

        val state = probe(client).inspect()

        assertTrue(state.available)
        assertEquals(listOf(TeeSoterAnomalyKind.KNOWN_RELAY_CPU_ID), state.anomalies.map { it.kind })
    }

    @Test
    fun `stock hal stopped before and after a signing session is reported`() {
        val state = probe(workingClient(), halStates = listOf("stopped", "stopped")).inspect()

        assertEquals(listOf(TeeSoterAnomalyKind.SOFTWARE_HAL_TAKEOVER), state.anomalies.map { it.kind })
    }

    @Test
    fun `on demand hal started by the probe is not reported`() {
        val state = probe(workingClient(), halStates = listOf("stopped", "running")).inspect()

        assertTrue(state.anomalies.isEmpty())
    }

    @Test
    fun `init sigh failure becomes damaged`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = true,
            hasAsk = false,
            askGenerateSuccess = true,
            askModelJson = CLEAN_MODEL_JSON,
            authGenerateSuccess = true,
            hasAuth = true,
            authModelJson = CLEAN_MODEL_JSON,
            sessionResult = SoterSessionResult().apply {
                resultCode = 7
                session = 0L
            },
        )

        val state = probe(client, halStates = listOf("stopped", "stopped")).inspect()

        assertTrue(state.serviceReachable)
        assertTrue(state.keyPrepared)
        assertFalse(state.signSessionAvailable)
        assertFalse(state.available)
        assertTrue(state.damaged)
        assertTrue(state.anomalies.isEmpty())
        assertTrue(client.initSighCalled)
    }

    @Test
    fun `key preparation failure becomes damaged`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = true,
            hasAsk = false,
            askGenerateSuccess = false,
            authGenerateSuccess = false,
            hasAuth = false,
        )

        val state = probe(client).inspect()

        assertTrue(state.serviceReachable)
        assertFalse(state.keyPrepared)
        assertFalse(state.signSessionAvailable)
        assertFalse(state.available)
        assertTrue(state.damaged)
        assertTrue(client.generateAskCalled)
        assertFalse(client.initSighCalled)
    }

    private fun probe(
        client: FakeSoterClient,
        environment: SoterEnvironmentSnapshot = SoterEnvironmentSnapshot(),
        halStates: List<String?> = emptyList(),
    ): SoterCapabilityProbe {
        val remainingHalStates = ArrayDeque(halStates)
        return SoterCapabilityProbe(
            client = client,
            environmentInspector = SoterEnvironmentInspector { environment },
            currentUid = { TEST_UID },
            vendorHalState = { remainingHalStates.removeFirstOrNull() },
        )
    }

    private fun workingClient(modelJson: String = CLEAN_MODEL_JSON) = FakeSoterClient(
        nativeSupport = true,
        coreType = SoterCore.IS_TREBLE,
        trebleConnected = true,
        hasAsk = true,
        askModelJson = modelJson,
        authGenerateSuccess = true,
        hasAuth = true,
        authModelJson = modelJson,
        sessionResult = SoterSessionResult().apply {
            resultCode = 0
            session = 42L
        },
    )
}

private class FakeSoterClient(
    private val nativeSupport: Boolean,
    private val coreType: Int,
    private val trebleConnected: Boolean,
    private var hasAsk: Boolean = false,
    private val askGenerateSuccess: Boolean = false,
    private val askModelJson: String? = null,
    private val authGenerateSuccess: Boolean = false,
    private val hasAuth: Boolean = false,
    private val authModelJson: String? = null,
    private val sessionResult: SoterSessionResult? = null,
) : SoterClient {

    var initTrebleCalled = false
    var generateAskCalled = false
    var initSighCalled = false
    var removeAuthCalled = false
    var removeAskCalled = false
    var trebleUid: Int? = null
    var trebleUidSetBeforeInit = false

    override fun setTrebleUid(uid: Int) {
        trebleUid = uid
        trebleUidSetBeforeInit = !initTrebleCalled
    }

    override fun tryToInitSoterBeforeTreble() = Unit

    override fun tryToInitSoterTreble() {
        initTrebleCalled = true
    }

    override fun setUp() = Unit

    override fun isNativeSupportSoter(): Boolean = nativeSupport

    override fun getSoterCoreType(): Int = coreType

    override fun isTrebleServiceConnected(): Boolean = trebleConnected

    override fun isSupportFingerprint(): Boolean = false

    override fun isSystemHasFingerprint(): Boolean = false

    override fun isSupportBiometric(biometricType: Int): Boolean = false

    override fun isSystemHasBiometric(biometricType: Int): Boolean = false

    override fun hasAppGlobalSecureKey(): Boolean = hasAsk

    override fun generateAppGlobalSecureKey(): SoterCoreResult? {
        generateAskCalled = true
        hasAsk = askGenerateSuccess
        return if (askGenerateSuccess) SoterCoreResult(0) else SoterCoreResult(6, "ask failed")
    }

    override fun getAppGlobalSecureKeyModel(): SoterPubKeyModel? =
        askModelJson?.let { SoterPubKeyModel(it, "") }

    override fun generateAuthKey(alias: String): SoterCoreResult? =
        if (authGenerateSuccess) SoterCoreResult(0) else SoterCoreResult(6, "auth failed")

    override fun hasAuthKey(alias: String): Boolean = hasAuth

    override fun getAuthKeyModel(alias: String): SoterPubKeyModel? =
        authModelJson?.let { SoterPubKeyModel(it, "") }

    override fun initSigh(alias: String, challenge: String): SoterSessionResult? {
        initSighCalled = true
        return sessionResult
    }

    override fun removeAuthKey(alias: String, autoDeleteAsk: Boolean): SoterCoreResult? {
        removeAuthCalled = true
        return SoterCoreResult(0)
    }

    override fun removeAppGlobalSecureKey(): SoterCoreResult? {
        removeAskCalled = true
        hasAsk = false
        return SoterCoreResult(0)
    }
}

private const val TEST_UID = 10234

private const val CLEAN_MODEL_JSON =
    """{"pub_key":"","cpu_id":"00000000201ca0e1874c2b3eac6b67c2","counter":1,"uid":"$TEST_UID"}"""
