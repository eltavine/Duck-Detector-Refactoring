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

package com.eltavine.duckdetector.features.tee.data.verification.crl

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefsStore
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkState
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject

fun interface CrlNetworkStatusProvider {
    fun isNetworkAvailable(): Boolean
}

fun interface CrlFeedFetcher {
    @Throws(Exception::class)
    fun fetch(): String
}

class CrlStatusService(
    private val consentStore: TeeNetworkPrefsStore,
    private val networkStatusProvider: CrlNetworkStatusProvider,
    private val feedFetcher: CrlFeedFetcher,
    private val clock: () -> Long = System::currentTimeMillis,
) {

    constructor(
        context: Context,
        consentStore: TeeNetworkPrefsStore,
    ) : this(
        consentStore = consentStore,
        networkStatusProvider = AndroidCrlNetworkStatusProvider(context.applicationContext),
        feedFetcher = HttpCrlFeedFetcher(),
    )

    suspend fun inspect(chain: List<X509Certificate>): CrlStatusResult {
        if (chain.isEmpty()) {
            return CrlStatusResult(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.INACTIVE,
                    summary = "No certificate chain available for revocation checks.",
                ),
            )
        }

        val prefs = consentStore.prefs.first()
        clearLegacyCacheIfNeeded(prefs)

        if (!prefs.consentAsked) {
            return CrlStatusResult(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.CONSENT_REQUIRED,
                    summary = "Online CRL check is awaiting startup consent.",
                ),
            )
        }

        if (!prefs.consentGranted) {
            return CrlStatusResult(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Online CRL disabled in Settings.",
                ),
            )
        }

        val preflightDetail = if (networkStatusProvider.isNetworkAvailable()) {
            null
        } else {
            "ConnectivityManager reported no active network path."
        }

        val downloadResult = downloadAndCache()
        return when (downloadResult) {
            is CrlDownloadResult.Success -> buildResult(
                chain = chain,
                entries = downloadResult.entries,
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ACTIVE,
                    summary = "Online revocation data refreshed successfully.",
                    detail = joinDetails(
                        preflightDetail?.let { "$it Direct HTTPS fetch still succeeded." },
                        "${downloadResult.entries.size} revocation entries loaded.",
                    ),
                ),
            )

            is CrlDownloadResult.Failure -> buildFailureResult(
                chain = chain,
                failure = downloadResult.failure.withPreflightDetail(preflightDetail),
            )
        }
    }

    private suspend fun downloadAndCache(): CrlDownloadResult {
        return withContext(Dispatchers.IO) {
            runCatching {
                val json = feedFetcher.fetch()
                val entries = parseStatusJson(json)
                CrlDownloadResult.Success(entries)
            }.getOrElse { throwable ->
                CrlDownloadResult.Failure(classifyFailure(throwable))
            }
        }
    }

    private fun buildFailureResult(
        chain: List<X509Certificate>,
        failure: CrlFailure,
    ): CrlStatusResult {
        return CrlStatusResult(
            networkState = TeeNetworkState(
                mode = TeeNetworkMode.ERROR,
                summary = failure.summary,
                detail = failure.detail,
            ),
        )
    }

    private fun buildResult(
        chain: List<X509Certificate>,
        entries: Map<String, CrlEntry>,
        networkState: TeeNetworkState,
    ): CrlStatusResult {
        val revoked = chain.mapNotNull { cert ->
            val serialHex = cert.serialNumber.toString(16).lowercase()
            val serialDec = cert.serialNumber.toString()
            val entry = entries[serialHex]
                ?: entries[serialDec]
                ?: entries[serialHex.trimStart('0').ifBlank { "0" }]
                ?: entries[serialDec.trimStart('0').ifBlank { "0" }]

            entry
                ?.takeIf { it.status == STATUS_REVOKED || it.status == STATUS_SUSPENDED }
                ?.let { matched ->
                    RevokedCertificate(
                        serial = "$serialHex / $serialDec",
                        reason = matched.reason ?: matched.status,
                    )
                }
        }

        return CrlStatusResult(
            networkState = networkState.copy(
                summary = buildRevocationSummary(
                    baseSummary = networkState.summary,
                    revokedCount = revoked.size,
                ),
            ),
            revokedCertificates = revoked,
        )
    }

    private fun buildRevocationSummary(
        baseSummary: String,
        revokedCount: Int,
    ): String {
        val verdict = if (revokedCount == 0) {
            "This certificate chain is not present in the revocation feed."
        } else {
            "This certificate chain matched $revokedCount revoked/suspended entr${if (revokedCount == 1) "y" else "ies"}."
        }
        return "$baseSummary $verdict"
    }

    private fun parseStatusJson(json: String): Map<String, CrlEntry> {
        val root = JSONObject(json)
        val entries = root.optJSONObject("entries") ?: root
        val result = linkedMapOf<String, CrlEntry>()
        val keys = entries.keys()
        while (keys.hasNext()) {
            val rawKey = keys.next()
            val serial = rawKey.lowercase()
            val entry = entries.optJSONObject(rawKey)
            if (entry != null) {
                result[serial] = CrlEntry(
                    status = entry.optString("status", "UNKNOWN"),
                    reason = entry.optString("reason").takeIf { it.isNotBlank() },
                )
            }
        }
        return result
    }

    private fun classifyFailure(throwable: Throwable): CrlFailure {
        return when (throwable) {
            is SocketTimeoutException -> CrlFailure(
                summary = "CRL refresh timed out.",
                detail = "Google's revocation feed did not respond within ${NETWORK_TIMEOUT_MS / 1000}s.",
            )

            is UnknownHostException -> CrlFailure(
                summary = "CRL host lookup failed.",
                detail = throwable.message ?: "The revocation host could not be resolved.",
            )

            is HttpStatusException -> CrlFailure(
                summary = "CRL server returned HTTP ${throwable.statusCode}.",
                detail = throwable.responseSnippet ?: throwable.statusMessage,
            )

            is JSONException -> CrlFailure(
                summary = "CRL response could not be parsed.",
                detail = throwable.message,
            )

            is SSLException -> CrlFailure(
                summary = "CRL TLS handshake failed.",
                detail = throwable.message,
            )

            is IOException -> CrlFailure(
                summary = "CRL connection failed.",
                detail = throwable.message,
            )

            else -> CrlFailure(
                summary = "CRL refresh failed.",
                detail = throwable.message,
            )
        }
    }

    private fun joinDetails(
        vararg parts: String?,
    ): String? {
        return parts
            .filterNotNull()
            .map(String::trim)
            .filter(String::isNotBlank)
            .joinToString(separator = " ")
            .takeIf { it.isNotBlank() }
    }

    private suspend fun clearLegacyCacheIfNeeded(prefs: TeeNetworkPrefs) {
        if (!prefs.crlCacheJson.isNullOrBlank() || prefs.crlFetchedAt > 0L) {
            consentStore.clearCache()
        }
    }

    companion object {
        private const val STATUS_URL = "https://android.googleapis.com/attestation/status"
        private const val NETWORK_TIMEOUT_MS = 5_000
        private const val STATUS_REVOKED = "REVOKED"
        private const val STATUS_SUSPENDED = "SUSPENDED"
    }
}

internal class AndroidCrlNetworkStatusProvider(
    private val context: Context,
) : CrlNetworkStatusProvider {

    override fun isNetworkAvailable(): Boolean {
        val connectivityManager =
            context.getSystemService(ConnectivityManager::class.java) ?: return false
        val activeNetwork = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
}

internal class HttpCrlFeedFetcher : CrlFeedFetcher {

    override fun fetch(): String {
        val connection = URL(STATUS_URL).openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = "GET"
            connection.connectTimeout = NETWORK_TIMEOUT_MS
            connection.readTimeout = NETWORK_TIMEOUT_MS
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("Accept", "application/json")

            val statusCode = connection.responseCode
            val body =
                (if (statusCode in 200..299) connection.inputStream else connection.errorStream)
                    ?.bufferedReader()
                    ?.use { reader -> reader.readText() }
                    .orEmpty()

            if (statusCode !in 200..299) {
                throw HttpStatusException(
                    statusCode = statusCode,
                    statusMessage = connection.responseMessage,
                    responseSnippet = body.take(200).takeIf { it.isNotBlank() },
                )
            }

            body
        } finally {
            connection.disconnect()
        }
    }

    private companion object {
        private const val STATUS_URL = "https://android.googleapis.com/attestation/status"
        private const val NETWORK_TIMEOUT_MS = 5_000
    }
}

data class CrlStatusResult(
    val networkState: TeeNetworkState,
    val revokedCertificates: List<RevokedCertificate> = emptyList(),
)

data class RevokedCertificate(
    val serial: String,
    val reason: String,
)

private sealed interface CrlDownloadResult {
    data class Success(val entries: Map<String, CrlEntry>) : CrlDownloadResult

    data class Failure(val failure: CrlFailure) : CrlDownloadResult
}

private data class CrlFailure(
    val summary: String,
    val detail: String? = null,
) {
    fun withPreflightDetail(preflightDetail: String?): CrlFailure {
        if (preflightDetail.isNullOrBlank()) {
            return this
        }
        return copy(
            detail = listOf(preflightDetail, detail).filterNotNull().joinToString(separator = " ")
        )
    }
}

private data class CrlEntry(
    val status: String,
    val reason: String?,
)

private class HttpStatusException(
    val statusCode: Int,
    val statusMessage: String?,
    val responseSnippet: String?,
) : IOException("HTTP $statusCode ${statusMessage.orEmpty()}".trim())
