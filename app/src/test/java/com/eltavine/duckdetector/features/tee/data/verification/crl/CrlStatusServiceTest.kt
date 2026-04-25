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

import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefs
import com.eltavine.duckdetector.features.tee.data.preferences.TeeNetworkPrefsStore
import com.eltavine.duckdetector.features.tee.domain.TeeNetworkMode
import java.math.BigInteger
import java.io.IOException
import java.net.SocketTimeoutException
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CrlStatusServiceTest {

    @Test
    fun `refreshes online revocation data without caching it`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCount = 0
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher {
                fetchCount += 1
                """{"entries":{"1":{"status":"REVOKED","reason":"keyCompromise"}}}"""
            },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertFalse(result.networkState.usedCache)
        assertEquals(1, fetchCount)
        assertEquals(1, result.revokedCertificates.size)
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
        assertEquals(null, store.current.crlCacheJson)
    }

    @Test
    fun `returns skipped when networking is disabled in settings`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCalled = false
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher {
                fetchCalled = true
                ""
            },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.SKIPPED, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("disabled in Settings"))
        assertFalse(fetchCalled)
    }

    @Test
    fun `reports offline when network is unavailable and cache is missing`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCount = 0
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { false },
            feedFetcher = CrlFeedFetcher {
                fetchCount += 1
                throw IOException("offline")
            },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertEquals(1, fetchCount)
        assertTrue(result.networkState.summary.contains("connection failed"))
        assertTrue(result.networkState.detail.orEmpty().contains("ConnectivityManager"))
        assertFalse(result.networkState.usedCache)
    }

    @Test
    fun `reported offline does not block successful direct fetch`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        var fetchCount = 0
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { false },
            feedFetcher = CrlFeedFetcher {
                fetchCount += 1
                """{"entries":{"1":{"status":"GOOD"}}}"""
            },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertEquals(1, fetchCount)
        assertTrue(result.networkState.summary.contains("not present in the revocation feed"))
        assertTrue(
            result.networkState.detail.orEmpty().contains("Direct HTTPS fetch still succeeded")
        )
    }

    @Test
    fun `matches revoked certificate when feed key is decimal`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher {
                """{"entries":{"26":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1a")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertEquals(1, result.revokedCertificates.size)
        assertTrue(result.revokedCertificates.single().serial.contains("1a / 26"))
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
    }

    @Test
    fun `reports timeout when refresh times out`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { throw SocketTimeoutException("timeout") },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("timed out"))
    }

    @Test
    fun `reports parse error when feed json is invalid`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { """{"entries":""" },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("parsed"))
    }

    @Test
    fun `clears legacy cache and does not use it as fallback`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = true,
                crlCacheJson = """{"entries":{"1":{"status":"REVOKED","reason":"cached"}}}""",
                crlFetchedAt = NOW - 1_000L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { throw IllegalStateException("boom") },
            clock = { NOW },
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertFalse(result.networkState.usingCacheFallback)
        assertFalse(result.networkState.usedCache)
        assertTrue(result.revokedCertificates.isEmpty())
        assertEquals(null, store.current.crlCacheJson)
        assertEquals(0L, store.current.crlFetchedAt)
    }

    private class FakeTeeNetworkPrefsStore(
        initial: TeeNetworkPrefs,
    ) : TeeNetworkPrefsStore {
        private val state = MutableStateFlow(initial)

        override val prefs: Flow<TeeNetworkPrefs> = state

        val current: TeeNetworkPrefs
            get() = state.value

        override suspend fun setConsent(granted: Boolean) {
            state.value = state.value.copy(
                consentAsked = true,
                consentGranted = granted,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            )
        }

        override suspend fun storeCrlCache(json: String?, fetchedAt: Long) {
            state.value = state.value.copy(
                crlCacheJson = json,
                crlFetchedAt = fetchedAt,
            )
        }

        override suspend fun clearCache() {
            state.value = state.value.copy(
                crlCacheJson = null,
                crlFetchedAt = 0L,
            )
        }
    }

    @Suppress("DEPRECATION")
    private class FakeX509Certificate(
        private val serialHex: String,
    ) : X509Certificate() {

        override fun getSerialNumber(): BigInteger = BigInteger(serialHex, 16)

        override fun getEncoded(): ByteArray = ByteArray(0)

        override fun verify(key: PublicKey?) = Unit

        override fun verify(key: PublicKey?, sigProvider: String?) = Unit

        override fun toString(): String = "FakeX509Certificate($serialHex)"

        override fun getPublicKey(): PublicKey {
            throw UnsupportedOperationException()
        }

        override fun checkValidity() = Unit

        override fun checkValidity(date: Date?) = Unit

        override fun getVersion(): Int = 3

        override fun getIssuerDN(): Principal = X500Principal("CN=issuer")

        override fun getSubjectDN(): Principal = X500Principal("CN=subject")

        override fun getNotBefore(): Date = Date(0L)

        override fun getNotAfter(): Date = Date(0L)

        override fun getTBSCertificate(): ByteArray = ByteArray(0)

        override fun getSignature(): ByteArray = ByteArray(0)

        override fun getSigAlgName(): String = "NONE"

        override fun getSigAlgOID(): String = "1.2.3"

        override fun getSigAlgParams(): ByteArray = ByteArray(0)

        override fun getIssuerUniqueID(): BooleanArray? = null

        override fun getSubjectUniqueID(): BooleanArray? = null

        override fun getKeyUsage(): BooleanArray? = null

        override fun getBasicConstraints(): Int = -1

        override fun getCriticalExtensionOIDs(): MutableSet<String>? = null

        override fun getExtensionValue(oid: String?): ByteArray? = null

        override fun getNonCriticalExtensionOIDs(): MutableSet<String>? = null

        override fun hasUnsupportedCriticalExtension(): Boolean = false

        override fun getExtendedKeyUsage(): MutableList<String>? = null

        override fun getSubjectAlternativeNames(): MutableCollection<MutableList<*>>? = null

        override fun getIssuerAlternativeNames(): MutableCollection<MutableList<*>>? = null

        override fun getSubjectX500Principal(): X500Principal = X500Principal("CN=subject")

        override fun getIssuerX500Principal(): X500Principal = X500Principal("CN=issuer")
    }

    private companion object {
        private const val NOW = 1_900_000_000_000L
    }
}
