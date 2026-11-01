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

package com.eltavine.duckdetector.features.networkrisk.data

import android.net.ConnectivityManager
import android.net.ProxyInfo
import android.net.Uri
import android.os.Build
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.eltavine.duckdetector.features.networkrisk.data.clients.NetworkClientCollector
import com.eltavine.duckdetector.features.networkrisk.data.network.AndroidNetworkCollector
import com.eltavine.duckdetector.features.networkrisk.data.network.toConfiguration
import com.eltavine.duckdetector.features.networkrisk.data.modules.Box4MagiskCollector
import com.eltavine.duckdetector.features.networkrisk.data.modules.BoxForRootCollector
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.features.networkrisk.domain.*
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import org.junit.Assert.*
import org.junit.Test
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith

/** Ordinary-UID smoke tests; fixture packages and proxy setting are configured outside the app. */
@RunWith(AndroidJUnit4::class)
class NetworkRiskRuntimeTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val arguments = InstrumentationRegistry.getArguments()

    @Test fun frameworkQueriesRemainScopedAndUnprivileged() {
        assertTrue(Process.myUid() >= 10000)
        val window = AndroidNetworkCollector(context).collect()
        assertTrue(window.attempts in 1..2)
        assertTrue(window.durationMs >= 0)
        assertNotEquals(ObservationState.UNAVAILABLE, window.snapshot.defaultNetwork.state)
        assertEquals(ObservationState.OBSERVED, window.snapshot.visibleNetworks.state)
        when (arguments.getString("expectedNetwork")) {
            "absent" -> {
                assertEquals(ObservationState.NOT_OBSERVED, window.snapshot.defaultNetwork.state)
            }
            "present" -> assertEquals(ObservationState.OBSERVED, window.snapshot.defaultNetwork.state)
        }
        when (arguments.getString("expectedProxy")) {
            "present" -> {
                assertEquals(ObservationState.OBSERVED, window.snapshot.defaultProxy.state)
                if (window.consistency == SampleConsistency.REPEATED) {
                    assertEquals(DetectionSeverity.WARNING, NetworkRiskReport(NetworkRiskStage.READY, network = window).toDetectorStatus().severity)
                }
            }
            "absent" -> assertEquals(ObservationState.NOT_OBSERVED, window.snapshot.defaultProxy.state)
        }
    }

    @Test fun pacConfigurationIsNotAStaticEndpoint() {
        val configuration = ProxyInfo.buildPacProxy(Uri.parse("http://127.0.0.1:9/fixture.pac")).toConfiguration()
        assertEquals(ProxyKind.PAC, configuration.kind)
        assertEquals(ProxySourceComparison.PAC_NOT_COMPARABLE, compareProxySources(
            NetworkObservation.observed(configuration), NetworkObservation.absent(), false))
    }

    @Test fun installedReleaseFixturesUseExactPackageAndSigningIdentity() {
        val inventory = NetworkClientCollector(context).collect()
        assertEquals(ObservationState.OBSERVED, inventory.state)
        assertEquals(if (Build.VERSION.SDK_INT >= 30) InstalledPackageVisibility.RESTRICTED else InstalledPackageVisibility.FULL, inventory.visibility)
        arguments.getString("expectedClients").orEmpty().split(',').filter { it.isNotEmpty() }.forEach { packageName ->
            val hit = inventory.clients.single { it.packageName == packageName }
            assertEquals(packageName, ObservationState.OBSERVED, hit.state)
            assertEquals(packageName, ClientIdentity.SIGNATURE_VERIFIED, hit.identity)
        }
    }

    @Test fun processLocalJvmOverrideIsAnInconclusiveDifference() {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val framework = manager.defaultProxy
        assumeTrue(framework?.pacFileUrl == null || framework.pacFileUrl == Uri.EMPTY)
        val previousHost = System.getProperty("http.proxyHost")
        val previousPort = System.getProperty("http.proxyPort")
        val differentPort = if (framework?.port == 7890) "7891" else "7890"
        try {
            System.setProperty("http.proxyHost", "jvm-override.invalid")
            System.setProperty("http.proxyPort", differentPort)
            val sources = requireNotNull(AndroidNetworkCollector(context).collect().snapshot.proxySources)
            assertEquals(NetworkObservation.observed(differentPort.toInt()), sources.jvmHttpProxy)
            assertEquals(ProxySourceComparison.DIFFERENT, sources.comparison)
            assertEquals(ObservationState.INCONCLUSIVE, sources.comparison.toObservationState())
            assertEquals(framework, manager.defaultProxy)
        } finally {
            if (previousHost == null) System.clearProperty("http.proxyHost") else System.setProperty("http.proxyHost", previousHost)
            if (previousPort == null) System.clearProperty("http.proxyPort") else System.setProperty("http.proxyPort", previousPort)
        }
    }

    @Test fun cleanEmulatorMetadataIsAbsentOrPermissionLimited() {
        listOf(Box4MagiskCollector().collect(), BoxForRootCollector().collect()).forEach { evidence ->
            assertTrue(evidence.metadata.state in setOf(ObservationState.NOT_OBSERVED, ObservationState.PERMISSION_LIMITED))
        }
    }
}
