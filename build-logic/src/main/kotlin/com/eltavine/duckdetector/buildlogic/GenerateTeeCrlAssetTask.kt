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

package com.eltavine.duckdetector.buildlogic

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL

internal const val TEE_CRL_GENERATED_ASSET_FILE_NAME = "tee_attestation_status.generated.json"
internal const val TEE_CRL_FALLBACK_ASSET_FILE_NAME = "tee_attestation_status.json"
internal const val TEE_CRL_STATUS_URL = "https://android.googleapis.com/attestation/status"

abstract class GenerateTeeCrlAssetTask : DefaultTask() {

    init {
        outputs.upToDateWhen {
            !refreshEnabled.get()
        }
    }

    @get:Input
    abstract val refreshEnabled: Property<Boolean>

    @get:Input
    abstract val endpointUrl: Property<String>

    @get:Input
    abstract val maxAttempts: Property<Int>

    @get:Input
    abstract val connectTimeoutMillis: Property<Int>

    @get:Input
    abstract val readTimeoutMillis: Property<Int>

    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val fallbackAsset: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val outputDir = outputDirectory.get().asFile
        val outputFile = outputDir.resolve(TEE_CRL_GENERATED_ASSET_FILE_NAME)
        outputDir.mkdirs()

        val refreshed = if (refreshEnabled.get()) {
            fetchWithRetries()
        } else {
            null
        }

        val json = refreshed?.let(::mergeFallbackEntries) ?: readFallbackAsset()
        outputFile.writeText(json, Charsets.UTF_8)
    }

    private fun fetchWithRetries(): String? {
        val attempts = maxAttempts.get().coerceAtLeast(1)
        var lastFailure: Throwable? = null
        repeat(attempts) { index ->
            val attempt = index + 1
            val result = runCatching { fetchRemoteStatus() }
            val json = result.getOrNull()
            if (json != null) {
                logger.lifecycle(
                    "Fetched TEE CRL snapshot from ${endpointUrl.get()} on attempt $attempt/$attempts."
                )
                return json
            }

            lastFailure = result.exceptionOrNull()
            logger.warn(
                "TEE CRL snapshot fetch attempt $attempt/$attempts failed: " +
                    "${lastFailure?.message ?: lastFailure?.javaClass?.simpleName.orEmpty()}"
            )
            if (attempt < attempts) {
                Thread.sleep((250L * attempt).coerceAtMost(1_250L))
            }
        }

        logger.warn(
            "TEE CRL snapshot refresh failed after $attempts attempts; falling back to local asset.",
            lastFailure,
        )
        return null
    }

    private fun fetchRemoteStatus(): String {
        val connection = URL(endpointUrl.get()).openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.connectTimeout = connectTimeoutMillis.get()
            connection.readTimeout = readTimeoutMillis.get()
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("Accept", "application/json")

            val statusCode = connection.responseCode
            val body =
                (if (statusCode in 200..299) connection.inputStream else connection.errorStream)
                    ?.bufferedReader(Charsets.UTF_8)
                    ?.use { reader -> reader.readText() }
                    .orEmpty()

            if (statusCode !in 200..299) {
                throw IOException("HTTP $statusCode ${connection.responseMessage.orEmpty()}".trim())
            }
            validateStatusJson(body)
            body
        } finally {
            connection.disconnect()
        }
    }

    private fun readFallbackAsset(): String {
        val fallback = fallbackAsset.orNull?.asFile
            ?: throw GradleException(
                "TEE CRL fallback asset is not configured. Expected " +
                    "src/main/assets/$TEE_CRL_FALLBACK_ASSET_FILE_NAME."
            )
        if (!fallback.isFile) {
            throw GradleException("TEE CRL fallback asset is missing: ${fallback.absolutePath}")
        }
        return fallback.readText(Charsets.UTF_8).also(::validateStatusJson)
    }

    private fun mergeFallbackEntries(json: String): String {
        val fallback = fallbackAsset.orNull?.asFile ?: return json
        if (!fallback.isFile) {
            return json
        }
        val remoteRoot = validatedStatusJson(json)
        val remoteEntries = remoteRoot.optJSONObject("entries")
            ?: throw GradleException("TEE CRL snapshot does not look like an attestation status feed.")
        val fallbackRoot = validatedStatusJson(fallback.readText(Charsets.UTF_8))
        val fallbackEntries = fallbackRoot.optJSONObject("entries")
            ?: throw GradleException("TEE CRL fallback asset does not look like an attestation status feed.")

        // The checked-in fallback asset is the repository-pinned revocation floor. Start from it,
        // then add remote-only entries so CI refresh strengthens the floor without weakening it.
        // 已入库的 fallback asset 是仓库固定的吊销下限；先以它为基线，再追加远端独有条目，确保 CI 刷新只增量强化。
        val remoteKeys = remoteEntries.keys()
        while (remoteKeys.hasNext()) {
            val key = remoteKeys.next()
            val remoteEntry = remoteEntries.getJSONObject(key)
            if (isLocalMassAbuseSerial(key) && remoteEntry.isRevokedOrSuspended()) {
                // 临时例外：构建增量真的拉到该序列号时，标记为远端来源，运行时不再降级成本地“大规模滥用”WARN。
                fallbackEntries.put(
                    LOCAL_MASS_ABUSE_SERIAL,
                    JSONObject(remoteEntry.toString()).put(DUCK_SOURCE_FIELD, DUCK_SOURCE_REMOTE),
                )
            } else if (fallbackEntries.has(key)) {
                continue
            } else {
                fallbackEntries.put(key, remoteEntry)
            }
        }
        return fallbackRoot.toString(2)
    }

    private fun validateStatusJson(json: String) {
        validatedStatusJson(json)
    }

    private fun validatedStatusJson(json: String): JSONObject {
        val root = try {
            JSONObject(json)
        } catch (exception: JSONException) {
            throw GradleException("TEE CRL snapshot is not a JSON object.", exception)
        }
        if (root.optJSONObject("entries") == null) {
            throw GradleException("TEE CRL snapshot does not look like an attestation status feed.")
        }
        return root
    }
}

private fun isLocalMassAbuseSerial(key: String): Boolean {
    val normalized = key.lowercase().trimStart('0').ifBlank { "0" }
    return normalized == LOCAL_MASS_ABUSE_SERIAL ||
        runCatching {
            BigInteger(key).toString(16).lowercase() == LOCAL_MASS_ABUSE_SERIAL
        }.getOrDefault(false)
}

private fun JSONObject.isRevokedOrSuspended(): Boolean {
    return when (optString("status")) {
        "REVOKED", "SUSPENDED" -> true
        else -> false
    }
}

private const val LOCAL_MASS_ABUSE_SERIAL = "8616ef30679ed43cc2b43e3c97a2319e"
private const val DUCK_SOURCE_FIELD = "_duckDetectorSource"
private const val DUCK_SOURCE_REMOTE = "REMOTE"
