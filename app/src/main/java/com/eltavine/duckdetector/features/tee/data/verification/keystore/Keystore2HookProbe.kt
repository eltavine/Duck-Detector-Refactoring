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

import android.os.Build

class Keystore2HookProbe(
    private val binderClient: Keystore2PrivateBinderClient = Keystore2PrivateBinderClient(),
) {

    fun inspect(): Keystore2HookResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2HookResult(
                available = false,
                detail = "Keystore2 raw transaction probe requires Android 12 or newer.",
            )
        }
        val binder = binderClient.lookupBinder() ?: return Keystore2HookResult(
            available = false,
            detail = "Keystore2 binder endpoint was not available.",
        )
        val alias = "duck_missing_key_${System.nanoTime()}"
        val transaction = binderClient.executeRequest(
            binder = binder,
            request = binderClient.buildGetKeyEntryRequest(alias),
        )
        if (!transaction.success) {
            return Keystore2HookResult(
                available = true,
                rawPrefix = transaction.replySnapshot?.rawPrefix,
                detail = transaction.replyFailureReason
                    ?: transaction.throwable?.message
                    ?: "Keystore2 transact() returned false.",
            )
        }
        return classifyKeystore2HookReply(transaction.replySnapshot)
    }
}

internal fun classifyKeystore2HookReply(snapshot: Keystore2ReplySnapshot?): Keystore2HookResult {
    if (snapshot == null) {
        return Keystore2HookResult(
            available = true,
            detail = "Keystore2 reply was empty.",
        )
    }
    if (snapshot.dataSize < 8) {
        return Keystore2HookResult(
            available = true,
            rawPrefix = snapshot.rawPrefix,
            detail = "Keystore2 reply was too small to fingerprint.",
        )
    }
    val exceptionCode = snapshot.exceptionCode
    if (exceptionCode != EX_SERVICE_SPECIFIC) {
        return Keystore2HookResult(
            available = true,
            rawPrefix = snapshot.rawPrefix,
            detail = if (exceptionCode == 0) {
                "Missing-key transaction unexpectedly succeeded."
            } else {
                "Keystore2 reply used exception code ${exceptionCode ?: "unknown"}."
            },
        )
    }
    val secondWord = snapshot.secondWord ?: return Keystore2HookResult(
        available = true,
        rawPrefix = snapshot.rawPrefix,
        detail = "Keystore2 reply was missing the secondary fingerprint word.",
    )
    return when {
        secondWord == RESPONSE_KEY_NOT_FOUND -> Keystore2HookResult(
            available = true,
            javaHookDetected = true,
            nativeStyleResponse = false,
            errorCode = RESPONSE_KEY_NOT_FOUND,
            rawPrefix = snapshot.rawPrefix,
            detail = "Keystore2 reply skipped the String16 slot and jumped straight to KEY_NOT_FOUND.",
        )

        secondWord == STRING16_NULL || secondWord >= 0 -> {
            val messageLength = secondWord
            val stackHeader = snapshot.trailingInts.getOrNull(0)
            val errorCode = snapshot.trailingInts.getOrNull(1)
            Keystore2HookResult(
                available = true,
                javaHookDetected = false,
                nativeStyleResponse = true,
                messageLength = messageLength,
                errorCode = errorCode,
                rawPrefix = snapshot.rawPrefix,
                detail = buildString {
                    append("Native-style Keystore2 reply")
                    append(" msgLen=")
                    append(messageLength)
                    stackHeader?.let {
                        append(" stack=")
                        append(it)
                    }
                    errorCode?.let {
                        append(" error=")
                        append(it)
                    }
                },
            )
        }

        else -> Keystore2HookResult(
            available = true,
            rawPrefix = snapshot.rawPrefix,
            detail = "Keystore2 reply used an unknown serialization fingerprint ($secondWord).",
        )
    }
}

data class Keystore2HookResult(
    val available: Boolean,
    val javaHookDetected: Boolean = false,
    val nativeStyleResponse: Boolean = false,
    val messageLength: Int? = null,
    val errorCode: Int? = null,
    val rawPrefix: String? = null,
    val detail: String,
)

private const val EX_SERVICE_SPECIFIC = -8
private const val STRING16_NULL = -1
private const val RESPONSE_KEY_NOT_FOUND = 7
