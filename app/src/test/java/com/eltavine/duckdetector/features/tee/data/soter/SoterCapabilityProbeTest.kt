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

package com.eltavine.duckdetector.features.tee.data.soter

import com.tencent.soter.core.SoterCore
import com.tencent.soter.core.model.SoterCoreResult
import com.tencent.soter.soterserver.SoterSessionResult
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

        val state = SoterCapabilityProbe(client).inspect()

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

        val state = SoterCapabilityProbe(
            client = client,
            environmentInspector = SoterEnvironmentInspector {
                SoterEnvironmentSnapshot(
                    supportExpected = true,
                    simplifiedChineseLocale = true,
                    servicePackageVisible = false,
                )
            },
        ).inspect()

        assertFalse(state.serviceReachable)
        assertFalse(state.damaged)
        assertTrue(state.abnormalEnvironment)
        assertTrue(state.summary.contains("abnormal soter environment", ignoreCase = true))
    }

    @Test
    fun `pre existing ask is not removed during cleanup`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = true,
            hasAsk = true,
            askModelPresent = true,
            authGenerateSuccess = true,
            hasAuth = true,
            authModelPresent = true,
            sessionResult = SoterSessionResult().apply {
                resultCode = 0
                session = 42L
            },
        )

        val state = SoterCapabilityProbe(client).inspect()

        assertTrue(state.available)
        assertFalse(state.damaged)
        assertTrue(client.removeAuthCalled)
        assertFalse(client.removeAskCalled)
    }

    @Test
    fun `init sigh failure becomes damaged`() {
        val client = FakeSoterClient(
            nativeSupport = true,
            coreType = SoterCore.IS_TREBLE,
            trebleConnected = true,
            hasAsk = false,
            askGenerateSuccess = true,
            askModelPresent = true,
            authGenerateSuccess = true,
            hasAuth = true,
            authModelPresent = true,
            sessionResult = SoterSessionResult().apply {
                resultCode = 7
                session = 0L
            },
        )

        val state = SoterCapabilityProbe(client).inspect()

        assertTrue(state.serviceReachable)
        assertTrue(state.keyPrepared)
        assertFalse(state.signSessionAvailable)
        assertFalse(state.available)
        assertTrue(state.damaged)
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
            askModelPresent = false,
            authGenerateSuccess = false,
            hasAuth = false,
            authModelPresent = false,
        )

        val state = SoterCapabilityProbe(client).inspect()

        assertTrue(state.serviceReachable)
        assertFalse(state.keyPrepared)
        assertFalse(state.signSessionAvailable)
        assertFalse(state.available)
        assertTrue(state.damaged)
        assertTrue(client.generateAskCalled)
        assertFalse(client.initSighCalled)
    }
}

private class FakeSoterClient(
    private val nativeSupport: Boolean,
    private val coreType: Int,
    private val trebleConnected: Boolean,
    private var hasAsk: Boolean = false,
    private val askGenerateSuccess: Boolean = false,
    private val askModelPresent: Boolean = false,
    private val authGenerateSuccess: Boolean = false,
    private val hasAuth: Boolean = false,
    private val authModelPresent: Boolean = false,
    private val sessionResult: SoterSessionResult? = null,
) : SoterClient {

    var initTrebleCalled = false
    var generateAskCalled = false
    var initSighCalled = false
    var removeAuthCalled = false
    var removeAskCalled = false

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

    override fun getAppGlobalSecureKeyModel(): Any? = if (askModelPresent) Any() else null

    override fun generateAuthKey(alias: String): SoterCoreResult? =
        if (authGenerateSuccess) SoterCoreResult(0) else SoterCoreResult(6, "auth failed")

    override fun hasAuthKey(alias: String): Boolean = hasAuth

    override fun getAuthKeyModel(alias: String): Any? = if (authModelPresent) Any() else null

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
