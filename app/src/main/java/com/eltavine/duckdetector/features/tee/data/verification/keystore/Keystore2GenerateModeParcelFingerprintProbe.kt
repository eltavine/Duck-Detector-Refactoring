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

data class Keystore2GenerateModeParcelFingerprintResult(
    val executed: Boolean,
    val available: Boolean = false,
    val authorizationCount: Int? = null,
    val lastAuthorizationSecLevel: Long? = null,
    val lastAuthorizationUnionTag: Long? = null,
    val lastAuthorizationHasUnknownUnionTag: Boolean = false,
    val modificationTimeMs: Long? = null,
    val matched: Boolean = false,
    val rawPrefix: String? = null,
    val detail: String,
)

class Keystore2GenerateModeParcelFingerprintProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
    private val parser: GenerateKeyReplyParcelParser = GenerateKeyReplyParcelParser(),
) {

    fun inspect(useStrongBox: Boolean = false): Keystore2GenerateModeParcelFingerprintResult {
        val capture = binderClient.captureGenerateKeyReply(useStrongBox)
        if (!capture.available) {
            return Keystore2GenerateModeParcelFingerprintResult(
                executed = false,
                available = false,
                rawPrefix = capture.rawPrefix,
                detail = capture.detail,
            )
        }

        val rawReply = capture.rawReply
        if (rawReply == null) {
            return Keystore2GenerateModeParcelFingerprintResult(
                executed = true,
                available = false,
                rawPrefix = capture.rawPrefix,
                detail = capture.detail,
            )
        }

        val parsed = parser.parse(rawReply = rawReply, rawPrefix = capture.rawPrefix)
        if (!parsed.parseSucceeded) {
            return Keystore2GenerateModeParcelFingerprintResult(
                executed = true,
                available = false,
                rawPrefix = parsed.rawPrefix,
                detail = parsed.detail,
            )
        }

        val matched =
            parsed.lastAuthorizationSecLevel == 256L &&
                parsed.lastAuthorizationHasUnknownUnionTag &&
                parsed.modificationTimeMs == 4294967297L

        return Keystore2GenerateModeParcelFingerprintResult(
            executed = true,
            available = true,
            authorizationCount = parsed.authorizationCount,
            lastAuthorizationSecLevel = parsed.lastAuthorizationSecLevel,
            lastAuthorizationUnionTag = parsed.lastAuthorizationUnionTag,
            lastAuthorizationHasUnknownUnionTag = parsed.lastAuthorizationHasUnknownUnionTag,
            modificationTimeMs = parsed.modificationTimeMs,
            matched = matched,
            rawPrefix = parsed.rawPrefix,
            detail = parsed.detail,
        )
    }
}
