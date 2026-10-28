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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.content.Context
import java.security.MessageDigest

/** A stable identity for one doPreload() execution, independent of the later carrier PID. */
internal data class SelinuxAppZygoteGenerationKey(
    val preloadPid: Int,
    val appUid: Int,
    val startedNanos: Long,
    val apkPath: String,
    val splitPaths: List<String>,
    val versionCode: Long,
    val payloadSchemaVersion: Int,
    val buildRevision: String,
) {
    fun storageKey(): String {
        val fields = listOf(
            preloadPid.toString(),
            appUid.toString(),
            startedNanos.toString(),
            apkPath,
            splitPaths.size.toString(),
            *splitPaths.toTypedArray(),
            versionCode.toString(),
            payloadSchemaVersion.toString(),
            buildRevision,
        )
        val canonical = buildString {
            fields.forEach { append(it.length).append(':').append(it) }
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
        val hex = "0123456789abcdef"
        return buildString(digest.size * 2) {
            digest.forEach { byte ->
                val value = byte.toInt() and 0xff
                append(hex[value ushr 4])
                append(hex[value and 0x0f])
            }
        }
    }
}

internal fun SelinuxCarrierProvenance.toGenerationKey(): SelinuxAppZygoteGenerationKey =
    SelinuxAppZygoteGenerationKey(
        preloadPid = preloadPid,
        appUid = appUid,
        startedNanos = startedNanos,
        apkPath = apkPath,
        splitPaths = splitPaths,
        versionCode = versionCode,
        payloadSchemaVersion = payloadSchemaVersion,
        buildRevision = buildRevision,
    )

internal enum class GenerationFenceCheck {
    NOT_ACCEPTED,
    ALREADY_ACCEPTED,
    UNAVAILABLE,
}

/** Persistent fence: a preload generation is accepted at most once, even after process restart. */
internal interface SelinuxAppZygoteGenerationStore {
    fun check(key: SelinuxAppZygoteGenerationKey): GenerationFenceCheck
    fun commitAccepted(key: SelinuxAppZygoteGenerationKey): Boolean
}

internal class SharedPreferencesSelinuxAppZygoteGenerationStore(
    context: Context,
) : SelinuxAppZygoteGenerationStore {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE,
    )

    override fun check(key: SelinuxAppZygoteGenerationKey): GenerationFenceCheck = runCatching {
        when (preferences.getString(LAST_ACCEPTED_KEY, null)) {
            key.storageKey() -> GenerationFenceCheck.ALREADY_ACCEPTED
            else -> GenerationFenceCheck.NOT_ACCEPTED
        }
    }.getOrDefault(GenerationFenceCheck.UNAVAILABLE)

    override fun commitAccepted(key: SelinuxAppZygoteGenerationKey): Boolean = runCatching {
        preferences.edit().putString(LAST_ACCEPTED_KEY, key.storageKey()).commit()
    }.getOrDefault(false)

    private companion object {
        const val PREFERENCES_NAME = "duck_app_zygote_generation_fence"
        const val LAST_ACCEPTED_KEY = "last_accepted_generation_sha256"
    }
}
