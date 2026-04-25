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

import android.content.Context
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.tencent.soter.core.SoterCore
import com.tencent.soter.core.model.ConstantsSoter
import com.tencent.soter.core.model.SoterCoreResult
import com.tencent.soter.soterserver.SoterSessionResult

class SoterCapabilityProbe internal constructor(
    private val client: SoterClient,
    private val environmentInspector: SoterEnvironmentInspector = SoterEnvironmentInspector {
        SoterEnvironmentSnapshot()
    },
    private val damageEvaluator: SoterDamageEvaluator = SoterDamageEvaluator(),
) {

    constructor(
        context: Context,
        damageEvaluator: SoterDamageEvaluator = SoterDamageEvaluator(),
    ) : this(
        AndroidSoterClient(context.applicationContext),
        AndroidSoterEnvironmentInspector(context.applicationContext),
        damageEvaluator,
    )

    fun inspect(): TeeSoterState {
        val result = runProbe()
        return damageEvaluator.evaluate(
            serviceReachable = result.initServiceOk,
            keyPrepared = result.keyPrepareOk,
            signSessionAvailable = result.signSessionOk,
            errorMessage = result.uiSummary,
            abnormalEnvironment = result.abnormalEnvironment,
        )
    }

    private fun runProbe(): ProbeResult {
        val testAlias = "$TEST_ALIAS_PREFIX${System.currentTimeMillis()}"
        val environment = runCatching { environmentInspector.inspect() }.getOrDefault(SoterEnvironmentSnapshot())

        var nativeSupport = false
        var coreType = 0
        var trebleConnected = false
        var askPreExisted = true
        var keyPrepareOk = false
        var signSessionOk = false
        var summary = "Soter probe did not complete."

        try {
            client.tryToInitSoterBeforeTreble()
            client.tryToInitSoterTreble()
            client.setUp()

            nativeSupport = runCatching { client.isNativeSupportSoter() }.getOrDefault(false)
            coreType = runCatching { client.getSoterCoreType() }.getOrDefault(0)
            trebleConnected = runCatching { client.isTrebleServiceConnected() }.getOrDefault(false)
            summary = "service nativeSupport=$nativeSupport, coreType=$coreType, trebleConnected=$trebleConnected"
        } catch (throwable: Throwable) {
            summary = "init failed with ${throwable.javaClass.simpleName}"
        }

        try {
            val fpHw = client.isSupportFingerprint()
            val fpEnrolled = client.isSystemHasFingerprint()
            val faceHw = client.isSupportBiometric(ConstantsSoter.FACEID_AUTH)
            val faceEnrolled = client.isSystemHasBiometric(ConstantsSoter.FACEID_AUTH)
            summary += ", biometric fpHw=$fpHw, fpEnrolled=$fpEnrolled, faceHw=$faceHw, faceEnrolled=$faceEnrolled"
        } catch (throwable: Throwable) {
            summary += ", biometric=${throwable.javaClass.simpleName}"
        }

        if (nativeSupport && trebleConnected) {
            try {
                val prepareState = prepareKeyLikeWechat(testAlias)
                askPreExisted = prepareState.askPreExisted
                keyPrepareOk = prepareState.keyPrepareOk
                summary += ", keyPrep ask=${prepareState.askOk}, askModel=${prepareState.askModelPresent}, auth=${prepareState.authOk}, hasAuth=${prepareState.authPresent}, authModel=${prepareState.authModelPresent}, retries=${prepareState.retryCount}, finalErr=${prepareState.finalErrCode}"
            } catch (throwable: Throwable) {
                summary += ", keyPrep=${throwable.javaClass.simpleName}"
            }
        } else {
            summary += ", keyPrep=skipped"
        }

        if (keyPrepareOk) {
            try {
                val challenge = "$TEST_CHALLENGE_PREFIX${System.currentTimeMillis()}"
                val sessionResult = client.initSigh(testAlias, challenge)
                signSessionOk =
                    sessionResult != null && sessionResult.resultCode == 0 && sessionResult.session != 0L
                val sessionId = sessionResult?.session ?: -1L
                summary += ", signing resultCode=${sessionResult?.resultCode ?: -1}, session=$sessionId"
            } catch (throwable: Throwable) {
                summary += ", signing=${throwable.javaClass.simpleName}"
            }
        } else {
            summary += ", signing=skipped"
        }

        var removeAuthOk = false
        var removeAskOk = false
        var removeAskSkipped = false
        try {
            val removeAuthResult = client.removeAuthKey(testAlias, false)
            removeAuthOk = removeAuthResult != null && removeAuthResult.isSuccess()
        } catch (_: Throwable) {
        }
        if (nativeSupport && trebleConnected) {
            if (!askPreExisted) {
                try {
                    val removeAskResult = client.removeAppGlobalSecureKey()
                    removeAskOk = removeAskResult != null &&
                        (removeAskResult.isSuccess() || isCleanupNonFatal(removeAskResult))
                } catch (_: Throwable) {
                }
            } else {
                removeAskSkipped = true
            }
        } else {
            removeAskSkipped = true
        }
        summary += ", cleanup removeAuth=$removeAuthOk, removeAsk=$removeAskOk, removeAskSkipped=$removeAskSkipped"

        val initServiceOk = nativeSupport && trebleConnected
        return ProbeResult(
            initServiceOk = initServiceOk,
            keyPrepareOk = keyPrepareOk,
            signSessionOk = signSessionOk,
            abnormalEnvironment = environment.abnormalEnvironment,
            uiSummary = summary,
        )
    }

    private fun prepareKeyLikeWechat(testAlias: String): PrepareState {
        val state = PrepareState(
            askPreExisted = runCatching { client.hasAppGlobalSecureKey() }.getOrDefault(false),
        )
        var lastErrCode = 0
        var lastErrMsg = "ok"

        repeat(MAX_WECHAT_PREPARE_RETRY) { attempt ->
            state.retryCount = attempt
            if (attempt == 1) {
                runCatching { client.removeAppGlobalSecureKey() }
            }

            var askExists = runCatching { client.hasAppGlobalSecureKey() }.getOrDefault(false)
            if (!askExists) {
                val askResult = runCatching { client.generateAppGlobalSecureKey() }.getOrNull()
                askExists = askResult?.isSuccess() == true
                if (askExists) {
                    state.askGeneratedByProbe = true
                } else {
                    lastErrCode = askResult?.errCode ?: UNKNOWN_RESULT_CODE
                    lastErrMsg = askResult?.errMsg ?: "ASK generate result null"
                    return@repeat
                }
            }

            state.askOk = askExists
            state.askModelPresent = runCatching { client.getAppGlobalSecureKeyModel() != null }.getOrDefault(false)
            if (!state.askModelPresent) {
                lastErrCode = ASK_MODEL_MISSING
                lastErrMsg = "ask model missing"
                return@repeat
            }

            val authResult = runCatching { client.generateAuthKey(testAlias) }.getOrNull()
            state.authOk = authResult?.isSuccess() == true
            if (!state.authOk) {
                lastErrCode = authResult?.errCode ?: UNKNOWN_RESULT_CODE
                lastErrMsg = authResult?.errMsg ?: "AuthKey generate result null"
                return@repeat
            }

            state.authPresent = runCatching { client.hasAuthKey(testAlias) }.getOrDefault(false)
            state.authModelPresent = runCatching { client.getAuthKeyModel(testAlias) != null }.getOrDefault(false)
            if (!state.authPresent || !state.authModelPresent) {
                lastErrCode = AUTH_MODEL_MISSING
                lastErrMsg = "auth key model is null or auth key absent after generation"
                return@repeat
            }

            state.keyPrepareOk = true
            state.finalErrCode = 0
            state.finalErrMsg = "ok"
            return state
        }

        state.finalErrCode = lastErrCode
        state.finalErrMsg = lastErrMsg
        return state
    }

    private fun isCleanupNonFatal(result: SoterCoreResult): Boolean {
        return result.errCode == 7 || result.errCode == -5 || result.errCode == -300
    }

    private class PrepareState(
        val askPreExisted: Boolean,
        var askGeneratedByProbe: Boolean = false,
        var askOk: Boolean = false,
        var askModelPresent: Boolean = false,
        var authOk: Boolean = false,
        var authPresent: Boolean = false,
        var authModelPresent: Boolean = false,
        var keyPrepareOk: Boolean = false,
        var retryCount: Int = 0,
        var finalErrCode: Int = 0,
        var finalErrMsg: String = "ok",
    )

    private class ProbeResult(
        val initServiceOk: Boolean,
        val keyPrepareOk: Boolean,
        val signSessionOk: Boolean,
        val abnormalEnvironment: Boolean,
        val uiSummary: String,
    )

    companion object {
        private const val TEST_ALIAS_PREFIX = "duckdetector_soter_probe_"
        private const val TEST_CHALLENGE_PREFIX = "duckdetector_probe_"
        private const val MAX_WECHAT_PREPARE_RETRY = 3
        private const val UNKNOWN_RESULT_CODE = -999
        private const val ASK_MODEL_MISSING = 1003
        private const val AUTH_MODEL_MISSING = 1006
    }
}

internal interface SoterClient {
    fun tryToInitSoterBeforeTreble()
    fun tryToInitSoterTreble()
    fun setUp()
    fun isNativeSupportSoter(): Boolean
    fun getSoterCoreType(): Int
    fun isTrebleServiceConnected(): Boolean
    fun isSupportFingerprint(): Boolean
    fun isSystemHasFingerprint(): Boolean
    fun isSupportBiometric(biometricType: Int): Boolean
    fun isSystemHasBiometric(biometricType: Int): Boolean
    fun hasAppGlobalSecureKey(): Boolean
    fun generateAppGlobalSecureKey(): SoterCoreResult?
    fun getAppGlobalSecureKeyModel(): Any?
    fun generateAuthKey(alias: String): SoterCoreResult?
    fun hasAuthKey(alias: String): Boolean
    fun getAuthKeyModel(alias: String): Any?
    fun initSigh(alias: String, challenge: String): SoterSessionResult?
    fun removeAuthKey(alias: String, autoDeleteAsk: Boolean): SoterCoreResult?
    fun removeAppGlobalSecureKey(): SoterCoreResult?
}

private class AndroidSoterClient(
    private val appContext: Context,
) : SoterClient {
    override fun tryToInitSoterBeforeTreble() = SoterCore.tryToInitSoterBeforeTreble()

    override fun tryToInitSoterTreble() = SoterCore.tryToInitSoterTreble(appContext)

    override fun setUp() = SoterCore.setUp()

    override fun isNativeSupportSoter(): Boolean = SoterCore.isNativeSupportSoter()

    override fun getSoterCoreType(): Int = SoterCore.getSoterCoreType()

    override fun isTrebleServiceConnected(): Boolean = SoterCore.isTrebleServiceConnected()

    override fun isSupportFingerprint(): Boolean =
        SoterCore.isSupportBiometric(appContext, ConstantsSoter.FINGERPRINT_AUTH)

    override fun isSystemHasFingerprint(): Boolean =
        SoterCore.isSystemHasBiometric(appContext, ConstantsSoter.FINGERPRINT_AUTH)

    override fun isSupportBiometric(biometricType: Int): Boolean =
        SoterCore.isSupportBiometric(appContext, biometricType)

    override fun isSystemHasBiometric(biometricType: Int): Boolean =
        SoterCore.isSystemHasBiometric(appContext, biometricType)

    override fun hasAppGlobalSecureKey(): Boolean = SoterCore.hasAppGlobalSecureKey()

    override fun generateAppGlobalSecureKey(): SoterCoreResult? = SoterCore.generateAppGlobalSecureKey()

    override fun getAppGlobalSecureKeyModel(): Any? = SoterCore.getAppGlobalSecureKeyModel()

    override fun generateAuthKey(alias: String): SoterCoreResult? = SoterCore.generateAuthKey(alias)

    override fun hasAuthKey(alias: String): Boolean = SoterCore.hasAuthKey(alias)

    override fun getAuthKeyModel(alias: String): Any? = SoterCore.getAuthKeyModel(alias)

    override fun initSigh(alias: String, challenge: String): SoterSessionResult? =
        SoterCore.initSigh(alias, challenge)

    override fun removeAuthKey(alias: String, autoDeleteAsk: Boolean): SoterCoreResult? =
        SoterCore.removeAuthKey(alias, autoDeleteAsk)

    override fun removeAppGlobalSecureKey(): SoterCoreResult? = SoterCore.removeAppGlobalSecureKey()
}
