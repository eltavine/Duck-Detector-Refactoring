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

fun interface CrlEmbeddedStatusProvider {
    @Throws(Exception::class)
    fun load(): String
}

class CrlStatusService(
    private val consentStore: TeeNetworkPrefsStore,
    private val networkStatusProvider: CrlNetworkStatusProvider,
    private val feedFetcher: CrlFeedFetcher,
    private val embeddedStatusProvider: CrlEmbeddedStatusProvider,
) {

    constructor(
        context: Context,
        consentStore: TeeNetworkPrefsStore,
    ) : this(
        consentStore = consentStore,
        networkStatusProvider = AndroidCrlNetworkStatusProvider(context.applicationContext),
        feedFetcher = HttpCrlFeedFetcher(),
        embeddedStatusProvider = AssetsCrlEmbeddedStatusProvider(context.applicationContext),
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

        val embeddedResult = loadEmbeddedSnapshot()
        if (embeddedResult is CrlSnapshotResult.Failure) {
            return CrlStatusResult(
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ERROR,
                    summary = embeddedResult.failure.summary,
                    detail = embeddedResult.failure.detail,
                ),
            )
        }
        val embeddedEntries = (embeddedResult as CrlSnapshotResult.Success).entries

        if (!prefs.consentAsked) {
            return buildResult(
                chain = chain,
                entries = embeddedEntries,
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.CONSENT_REQUIRED,
                    summary = "Built-in revocation snapshot is active; online refresh is awaiting startup consent.",
                    cacheEntries = embeddedEntries.size,
                    usedCache = true,
                ),
            )
        }

        if (!prefs.consentGranted) {
            return buildResult(
                chain = chain,
                entries = embeddedEntries,
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.SKIPPED,
                    summary = "Built-in revocation snapshot is active; online refresh is disabled in Settings.",
                    cacheEntries = embeddedEntries.size,
                    usedCache = true,
                ),
            )
        }

        val preflightDetail = if (networkStatusProvider.isNetworkAvailable()) {
            null
        } else {
            "ConnectivityManager reported no active network path."
        }

        val downloadResult = downloadSnapshot()
        return when (downloadResult) {
            is CrlSnapshotResult.Success -> buildResult(
                chain = chain,
                entries = mergeOnlineEntries(
                    embeddedEntries = embeddedEntries,
                    onlineEntries = downloadResult.entries,
                ),
                networkState = TeeNetworkState(
                    mode = TeeNetworkMode.ACTIVE,
                    summary = "Online revocation data refreshed successfully.",
                    detail = joinDetails(
                        preflightDetail?.let { "$it Direct HTTPS fetch still succeeded." },
                        "${downloadResult.entries.size} revocation entries loaded.",
                    ),
                ),
            )

            is CrlSnapshotResult.Failure -> {
                val failure = downloadResult.failure.withPreflightDetail(preflightDetail)
                buildResult(
                    chain = chain,
                    entries = embeddedEntries,
                    networkState = TeeNetworkState(
                        mode = TeeNetworkMode.ERROR,
                        summary = "Online CRL refresh failed; built-in revocation snapshot was used.",
                        detail = joinDetails(
                            failure.summary,
                            failure.detail,
                        ),
                        cacheEntries = embeddedEntries.size,
                        usedCache = true,
                        usingCacheFallback = true,
                    ),
                )
            }
        }
    }

    private suspend fun loadEmbeddedSnapshot(): CrlSnapshotResult {
        return withContext(Dispatchers.IO) {
            runCatching {
                val json = embeddedStatusProvider.load()
                val entries = parseStatusJson(
                    json = json,
                    defaultSource = CrlEntrySource.EMBEDDED,
                )
                CrlSnapshotResult.Success(entries)
            }.getOrElse { throwable ->
                CrlSnapshotResult.Failure(classifyEmbeddedFailure(throwable))
            }
        }
    }

    private suspend fun downloadSnapshot(): CrlSnapshotResult {
        return withContext(Dispatchers.IO) {
            runCatching {
                val json = feedFetcher.fetch()
                val entries = parseStatusJson(
                    json = json,
                    defaultSource = CrlEntrySource.ONLINE,
                )
                CrlSnapshotResult.Success(entries)
            }.getOrElse { throwable ->
                CrlSnapshotResult.Failure(classifyFailure(throwable))
            }
        }
    }

    private fun mergeOnlineEntries(
        embeddedEntries: Map<String, CrlEntry>,
        onlineEntries: Map<String, CrlEntry>,
    ): Map<String, CrlEntry> {
        if (onlineEntries.isEmpty()) {
            return embeddedEntries
        }
        // Built-in revocations are the local trust floor; online data can add entries but cannot
        // downgrade a serial that the repository already marks revoked or suspended.
        // 内置吊销是本地信任下限；在线数据可以追加条目，但不能降级仓库已标记吊销/暂停的序列号。
        return LinkedHashMap<String, CrlEntry>(embeddedEntries).apply {
            onlineEntries.forEach { (serial, entry) ->
                val existing = this[serial]
                if (existing?.isLocalMassAbuseOverride(serial) == true && entry.isRevokedOrSuspended()) {
                    // 临时例外：该本地硬编码序列号只是“大规模滥用”WARN，联网/构建增量命中时恢复标准 CRL 语义。
                    this[serial] = entry
                } else {
                    putIfAbsent(serial, entry)
                }
            }
        }
    }

    private fun buildResult(
        chain: List<X509Certificate>,
        entries: Map<String, CrlEntry>,
        networkState: TeeNetworkState,
    ): CrlStatusResult {
        val revoked = chain.mapNotNull { cert ->
            val serialHex = cert.serialNumber.toString(16).lowercase()
            val serialDec = cert.serialNumber.toString()
            val candidates = listOfNotNull(
                entries[serialHex],
                entries[serialDec],
                entries[serialHex.trimStart('0').ifBlank { "0" }],
                entries[serialDec.trimStart('0').ifBlank { "0" }],
            )
            val entry = candidates.firstOrNull {
                it.source == CrlEntrySource.ONLINE &&
                    (it.status == STATUS_REVOKED || it.status == STATUS_SUSPENDED)
            } ?: candidates.firstOrNull()

            entry
                ?.takeIf { it.status == STATUS_REVOKED || it.status == STATUS_SUSPENDED }
                ?.let { matched ->
                    val evidenceKind = matched.evidenceKind(serialHex)
                    RevokedCertificate(
                        serial = "$serialHex / $serialDec",
                        reason = if (evidenceKind == RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE) {
                            "MASS_ABUSE"
                        } else {
                            matched.reason ?: matched.status
                        },
                        evidenceKind = evidenceKind,
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

    private fun parseStatusJson(
        json: String,
        defaultSource: CrlEntrySource,
    ): Map<String, CrlEntry> {
        val root = JSONObject(json)
        val entries = root.optJSONObject("entries")
            ?: throw JSONException("Attestation status feed is missing an entries object.")
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
                    source = entry.optString(DUCK_SOURCE_FIELD)
                        .takeIf { it == DUCK_SOURCE_REMOTE }
                        ?.let { CrlEntrySource.ONLINE }
                        ?: defaultSource,
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

    private fun classifyEmbeddedFailure(throwable: Throwable): CrlFailure {
        return when (throwable) {
            is JSONException -> CrlFailure(
                summary = "Built-in CRL snapshot could not be parsed.",
                detail = throwable.message,
            )

            is IOException -> CrlFailure(
                summary = "Built-in CRL snapshot could not be loaded.",
                detail = throwable.message,
            )

            else -> CrlFailure(
                summary = "Built-in CRL snapshot failed.",
                detail = throwable.message,
            )
        }
    }

    private fun CrlEntry.evidenceKind(serialHex: String): RevokedCertificateEvidenceKind {
        return if (isLocalMassAbuseOverride(serialHex)) {
            RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE
        } else {
            RevokedCertificateEvidenceKind.STANDARD_REVOCATION
        }
    }

    private fun CrlEntry.isRevokedOrSuspended(): Boolean {
        return status == STATUS_REVOKED || status == STATUS_SUSPENDED
    }

    private fun CrlEntry.isLocalMassAbuseOverride(serial: String): Boolean {
        return source == CrlEntrySource.EMBEDDED &&
            status == STATUS_REVOKED &&
            serial.trimStart('0').ifBlank { "0" } == LOCAL_MASS_ABUSE_SERIAL
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
        private const val NETWORK_TIMEOUT_MS = 5_000
        private const val STATUS_REVOKED = "REVOKED"
        private const val STATUS_SUSPENDED = "SUSPENDED"
        private const val LOCAL_MASS_ABUSE_SERIAL = "8616ef30679ed43cc2b43e3c97a2319e"
        private const val DUCK_SOURCE_FIELD = "_duckDetectorSource"
        private const val DUCK_SOURCE_REMOTE = "REMOTE"
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
    val evidenceKind: RevokedCertificateEvidenceKind = RevokedCertificateEvidenceKind.STANDARD_REVOCATION,
)

enum class RevokedCertificateEvidenceKind {
    STANDARD_REVOCATION,
    LOCAL_MASS_ABUSE,
}

internal class AssetsCrlEmbeddedStatusProvider(
    private val context: Context,
) : CrlEmbeddedStatusProvider {

    override fun load(): String {
        val assetManager = context.assets
        val assetName = if (assetManager.list("").orEmpty().contains(GENERATED_ASSET_FILE_NAME)) {
            GENERATED_ASSET_FILE_NAME
        } else {
            FALLBACK_ASSET_FILE_NAME
        }
        return assetManager.open(assetName).bufferedReader(Charsets.UTF_8).use { reader ->
            reader.readText()
        }
    }

    private companion object {
        private const val GENERATED_ASSET_FILE_NAME = "tee_attestation_status.generated.json"
        private const val FALLBACK_ASSET_FILE_NAME = "tee_attestation_status.json"
    }
}

private sealed interface CrlSnapshotResult {
    data class Success(val entries: Map<String, CrlEntry>) : CrlSnapshotResult

    data class Failure(val failure: CrlFailure) : CrlSnapshotResult
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
    val source: CrlEntrySource,
)

private enum class CrlEntrySource {
    EMBEDDED,
    ONLINE,
}

private class HttpStatusException(
    val statusCode: Int,
    val statusMessage: String?,
    val responseSnippet: String?,
) : IOException("HTTP $statusCode ${statusMessage.orEmpty()}".trim())
