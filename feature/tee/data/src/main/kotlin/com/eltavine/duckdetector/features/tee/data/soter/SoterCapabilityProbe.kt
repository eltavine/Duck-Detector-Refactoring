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

import android.content.Context
import android.os.Process
import com.eltavine.duckdetector.capability.systemproperties.data.SystemPropertyReadUtils
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.tee.domain.TeeSoterState
import com.tencent.soter.core.model.ConstantsSoter
import com.tencent.soter.core.model.SoterCoreResult
import com.tencent.soter.core.model.SoterPubKeyModel

class SoterCapabilityProbe internal constructor(
    private val client: SoterClient,
    private val environmentInspector: SoterEnvironmentInspector = SoterEnvironmentInspector {
        SoterEnvironmentSnapshot()
    },
    private val damageEvaluator: SoterDamageEvaluator = SoterDamageEvaluator(),
    private val abuseAnalyzer: SoterAbuseAnalyzer = SoterAbuseAnalyzer(),
    private val currentUid: () -> Int = Process::myUid,
    private val soterHalStates: () -> Map<String, String> = {
        SystemPropertyReadUtils().collectByPrefix(INIT_SERVICE_PROPERTY_PREFIX)
            .filterKeys { propertyName -> propertyName.contains(SOTER_SERVICE_NAME, ignoreCase = true) }
    },
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
            anomalies = abuseAnalyzer.analyze(result.keys, result.service),
        )
    }

    private fun runProbe(): ProbeResult {
        val testAlias = "$TEST_ALIAS_PREFIX${System.currentTimeMillis()}"
        val environment = runCatching { environmentInspector.inspect() }.getOrDefault(SoterEnvironmentSnapshot())
        val requestedUid = currentUid()

        var nativeSupport = false
        var coreType = 0
        var trebleConnected = false
        var askPreExisted = true
        var keyPrepareOk = false
        var signSessionOk = false
        var halStatesBeforePrepare: Map<String, String> = emptyMap()
        var halStatesAfterSigning: Map<String, String> = emptyMap()
        val keyEvidence = mutableListOf<SoterKeyEvidence>()
        var summary = "Soter probe did not complete."

        try {
            // SoterCoreTreble sends this static uid with every ISoterService call and leaves it at 0,
            // a key slot shared by every app that never sets it. The TA writes it into each blob.
            client.setTrebleUid(requestedUid)
            client.tryToInitSoterBeforeTreble()
            client.tryToInitSoterTreble()
            client.setUp()

            nativeSupport = runCatching { client.isNativeSupportSoter() }.getOrDefault(false)
            coreType = runCatching { client.getSoterCoreType() }.getOrDefault(0)
            trebleConnected = runCatching { client.isTrebleServiceConnected() }.getOrDefault(false)
            summary = "service nativeSupport=$nativeSupport, coreType=$coreType, trebleConnected=$trebleConnected"
        } catch (throwable: Throwable) {
            summary = "init failed with ${PlatformFailureName.of(throwable)}"
        }

        try {
            val fpHw = client.isSupportFingerprint()
            val fpEnrolled = client.isSystemHasFingerprint()
            val faceHw = client.isSupportBiometric(ConstantsSoter.FACEID_AUTH)
            val faceEnrolled = client.isSystemHasBiometric(ConstantsSoter.FACEID_AUTH)
            summary += ", biometric fpHw=$fpHw, fpEnrolled=$fpEnrolled, faceHw=$faceHw, faceEnrolled=$faceEnrolled"
        } catch (throwable: Throwable) {
            summary += ", biometric=${PlatformFailureName.of(throwable)}"
        }

        if (nativeSupport && trebleConnected) {
            try {
                halStatesBeforePrepare = soterHalStates()
                val prepareState = prepareKeyLikeWechat(testAlias)
                keyEvidence += keyEvidence(prepareState)
                askPreExisted = prepareState.askPreExisted
                keyPrepareOk = prepareState.keyPrepareOk
                summary += ", keyPrep ask=${prepareState.askOk}, askModel=${prepareState.askModelPresent}, auth=${prepareState.authOk}, hasAuth=${prepareState.authPresent}, authModel=${prepareState.authModelPresent}, retries=${prepareState.retryCount}, finalErr=${prepareState.finalErrCode}"
            } catch (throwable: Throwable) {
                summary += ", keyPrep=${PlatformFailureName.of(throwable)}"
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
                summary += ", signing=${PlatformFailureName.of(throwable)}"
            }
        } else {
            summary += ", signing=skipped"
        }
        if (signSessionOk) {
            halStatesAfterSigning = soterHalStates()
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
            keys = keyEvidence,
            // An on-demand HAL reads stopped until the first call starts it, so only a HAL that is
            // stopped both before the calls and after the signing session opened cannot have answered.
            service = SoterServiceEvidence(
                requestedUid = requestedUid,
                vendorHalStoppedWhileServing = signSessionOk &&
                    halStatesBeforePrepare.values.all { it.equals(VENDOR_HAL_STOPPED, ignoreCase = true) } &&
                    halStatesAfterSigning.values.all { it.equals(VENDOR_HAL_STOPPED, ignoreCase = true) } &&
                    halStatesBeforePrepare.isNotEmpty() &&
                    halStatesAfterSigning.isNotEmpty(),
            ),
            uiSummary = summary,
        )
    }

    private fun keyEvidence(state: PrepareState): List<SoterKeyEvidence> = buildList {
        state.askModel?.let { add(SoterKeyEvidence(SoterKeyRole.ASK, it.rawJson, it.signature)) }
        state.authModel?.let { add(SoterKeyEvidence(SoterKeyRole.AUTH_KEY, it.rawJson, it.signature)) }
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
            val askModel = runCatching { client.getAppGlobalSecureKeyModel() }.getOrNull()
            state.askModelPresent = askModel != null
            if (!state.askModelPresent) {
                lastErrCode = ASK_MODEL_MISSING
                lastErrMsg = "ask model missing"
                return@repeat
            }
            state.askModel = askModel

            val authResult = runCatching { client.generateAuthKey(testAlias) }.getOrNull()
            state.authOk = authResult?.isSuccess() == true
            if (!state.authOk) {
                lastErrCode = authResult?.errCode ?: UNKNOWN_RESULT_CODE
                lastErrMsg = authResult?.errMsg ?: "AuthKey generate result null"
                return@repeat
            }

            state.authPresent = runCatching { client.hasAuthKey(testAlias) }.getOrDefault(false)
            val authModel = runCatching { client.getAuthKeyModel(testAlias) }.getOrNull()
            state.authModelPresent = authModel != null
            if (!state.authPresent || !state.authModelPresent) {
                lastErrCode = AUTH_MODEL_MISSING
                lastErrMsg = "auth key model is null or auth key absent after generation"
                return@repeat
            }
            state.authModel = authModel

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
        var askModel: SoterPubKeyModel? = null,
        var authModel: SoterPubKeyModel? = null,
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
        val keys: List<SoterKeyEvidence>,
        val service: SoterServiceEvidence,
        val uiSummary: String,
    )

    companion object {
        private const val TEST_ALIAS_PREFIX = "duckdetector_soter_probe_"
        private const val TEST_CHALLENGE_PREFIX = "duckdetector_probe_"
        private const val MAX_WECHAT_PREPARE_RETRY = 3
        private const val UNKNOWN_RESULT_CODE = -999
        private const val ASK_MODEL_MISSING = 1003
        private const val AUTH_MODEL_MISSING = 1006
        private const val INIT_SERVICE_PROPERTY_PREFIX = "init.svc."
        private const val SOTER_SERVICE_NAME = "soter"
        private const val VENDOR_HAL_STOPPED = "stopped"
    }
}
