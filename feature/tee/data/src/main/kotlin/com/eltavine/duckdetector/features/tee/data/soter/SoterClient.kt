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
import com.tencent.soter.core.SoterCore
import com.tencent.soter.core.model.ConstantsSoter
import com.tencent.soter.core.model.SoterCoreResult
import com.tencent.soter.core.model.SoterPubKeyModel
import com.tencent.soter.core.sotercore.SoterCoreTreble
import com.tencent.soter.soterserver.SoterSessionResult

internal interface SoterClient {
    fun setTrebleUid(uid: Int)
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
    fun getAppGlobalSecureKeyModel(): SoterPubKeyModel?
    fun generateAuthKey(alias: String): SoterCoreResult?
    fun hasAuthKey(alias: String): Boolean
    fun getAuthKeyModel(alias: String): SoterPubKeyModel?
    fun initSigh(alias: String, challenge: String): SoterSessionResult?
    fun removeAuthKey(alias: String, autoDeleteAsk: Boolean): SoterCoreResult?
    fun removeAppGlobalSecureKey(): SoterCoreResult?
}

internal class AndroidSoterClient(
    private val appContext: Context,
) : SoterClient {
    override fun setTrebleUid(uid: Int) {
        SoterCoreTreble.uid = uid
    }

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

    override fun getAppGlobalSecureKeyModel(): SoterPubKeyModel? = SoterCore.getAppGlobalSecureKeyModel()

    override fun generateAuthKey(alias: String): SoterCoreResult? = SoterCore.generateAuthKey(alias)

    override fun hasAuthKey(alias: String): Boolean = SoterCore.hasAuthKey(alias)

    override fun getAuthKeyModel(alias: String): SoterPubKeyModel? = SoterCore.getAuthKeyModel(alias)

    override fun initSigh(alias: String, challenge: String): SoterSessionResult? =
        SoterCore.initSigh(alias, challenge)

    override fun removeAuthKey(alias: String, autoDeleteAsk: Boolean): SoterCoreResult? =
        SoterCore.removeAuthKey(alias, autoDeleteAsk)

    override fun removeAppGlobalSecureKey(): SoterCoreResult? = SoterCore.removeAppGlobalSecureKey()
}
