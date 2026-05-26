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
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{}}"""
            ),
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
    fun `uses built in revocation snapshot when online refresh is disabled`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.SKIPPED, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("online refresh is disabled in Settings"))
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
        assertFalse(fetchCalled)
    }

    @Test
    fun `falls back to built in snapshot when online refresh fails`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertEquals(1, fetchCount)
        assertTrue(result.networkState.summary.contains("built-in revocation snapshot was used"))
        assertTrue(result.networkState.detail.orEmpty().contains("ConnectivityManager"))
        assertTrue(result.networkState.usedCache)
        assertTrue(result.networkState.usingCacheFallback)
        assertEquals(1, result.revokedCertificates.size)
    }

    @Test
    fun `online refresh does not downgrade built in revocations`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertEquals(1, fetchCount)
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
        assertTrue(
            result.networkState.detail.orEmpty().contains("Direct HTTPS fetch still succeeded")
        )
        assertEquals(1, result.revokedCertificates.size)
        assertEquals("embedded", result.revokedCertificates.single().reason)
    }

    @Test
    fun `local hardcoded abuse serial is classified as mass abuse warning evidence`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { """{"entries":{}}""" },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("MASS_ABUSE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `online hardcoded abuse serial remains standard revocation evidence`() = runBlocking {
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
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("KEY_COMPROMISE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.STANDARD_REVOCATION,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `online decimal hardcoded abuse serial overrides local hex warning evidence`() = runBlocking {
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
                """{"entries":{"${LOCAL_MASS_ABUSE_SERIAL_DEC}":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("KEY_COMPROMISE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.STANDARD_REVOCATION,
            result.revokedCertificates.single().evidenceKind,
        )
    }

    @Test
    fun `online good status does not suppress local mass abuse warning evidence`() = runBlocking {
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
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"GOOD"}}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"8616ef30679ed43cc2b43e3c97a2319e":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate(LOCAL_MASS_ABUSE_SERIAL)))

        assertEquals(1, result.revokedCertificates.size)
        assertEquals("MASS_ABUSE", result.revokedCertificates.single().reason)
        assertEquals(
            RevokedCertificateEvidenceKind.LOCAL_MASS_ABUSE,
            result.revokedCertificates.single().evidenceKind,
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
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1a")))

        assertEquals(TeeNetworkMode.ACTIVE, result.networkState.mode)
        assertEquals(1, result.revokedCertificates.size)
        assertTrue(result.revokedCertificates.single().serial.contains("1a / 26"))
        assertTrue(result.networkState.summary.contains("matched 1 revoked/suspended entry"))
    }

    @Test
    fun `reports timeout detail while using built in snapshot`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("built-in revocation snapshot was used"))
        assertTrue(result.networkState.detail.orEmpty().contains("timed out"))
        assertTrue(result.networkState.usedCache)
    }

    @Test
    fun `reports online parse error while using built in snapshot`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":{}}"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.detail.orEmpty().contains("parsed"))
        assertTrue(result.networkState.usedCache)
    }

    @Test
    fun `reports malformed online feed while using built in snapshot`() = runBlocking {
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
            feedFetcher = CrlFeedFetcher { """{"entries":[]}""" },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.detail.orEmpty().contains("missing an entries object"))
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
    }

    @Test
    fun `clears legacy cache and uses embedded snapshot as fallback`() = runBlocking {
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
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.usingCacheFallback)
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
        assertEquals(null, store.current.crlCacheJson)
        assertEquals(0L, store.current.crlFetchedAt)
    }

    @Test
    fun `unanswered online refresh consent still uses built in snapshot`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = false,
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
                """{"entries":{}}"""
            },
            embeddedStatusProvider = embeddedStatusProvider(
                """{"entries":{"1":{"status":"REVOKED","reason":"embedded"}}}"""
            ),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.CONSENT_REQUIRED, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("online refresh is awaiting startup consent"))
        assertTrue(result.networkState.usedCache)
        assertEquals(1, result.revokedCertificates.size)
        assertFalse(fetchCalled)
    }

    @Test
    fun `reports embedded snapshot parse error`() = runBlocking {
        val store = FakeTeeNetworkPrefsStore(
            TeeNetworkPrefs(
                consentAsked = true,
                consentGranted = false,
                crlCacheJson = null,
                crlFetchedAt = 0L,
            ),
        )
        val service = CrlStatusService(
            consentStore = store,
            networkStatusProvider = CrlNetworkStatusProvider { true },
            feedFetcher = CrlFeedFetcher { """{"entries":{}}""" },
            embeddedStatusProvider = embeddedStatusProvider("""{"entries":"""),
        )

        val result = service.inspect(listOf(FakeX509Certificate("1")))

        assertEquals(TeeNetworkMode.ERROR, result.networkState.mode)
        assertTrue(result.networkState.summary.contains("Built-in CRL snapshot could not be parsed"))
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

    private fun embeddedStatusProvider(json: String): CrlEmbeddedStatusProvider {
        return CrlEmbeddedStatusProvider { json }
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
        private const val LOCAL_MASS_ABUSE_SERIAL = "8616ef30679ed43cc2b43e3c97a2319e"
        private const val LOCAL_MASS_ABUSE_SERIAL_DEC =
            "178235633296982535164483918324719301022"
    }
}
