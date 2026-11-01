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

package com.eltavine.duckdetector.features.networkrisk.domain

import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import org.junit.Assert.*
import org.junit.Test

class NetworkRiskReportStatusTest {
    @Test fun `observed deployment metadata raises warning`() {
        val report = NetworkRiskReport(
            NetworkRiskStage.READY,
            network = window(SampleConsistency.REPEATED),
            modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK, NetworkObservation.observed("v5.1"))),
        )
        assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
        assertEquals(DetectorStatus.info(InfoKind.ERROR), NetworkRiskReport.failed("failure").toDetectorStatus())
    }

    @Test fun `network change invalidates both positive and negative correlations`() {
        val sample = window(SampleConsistency.CHANGED)
        assertEquals(ObservationState.INCONCLUSIVE, sample.stateFor(ObservationState.OBSERVED))
        assertEquals(ObservationState.INCONCLUSIVE, sample.stateFor(ObservationState.NOT_OBSERVED))
        listOf(ObservationState.PERMISSION_LIMITED, ObservationState.UNAVAILABLE, ObservationState.UNSUPPORTED).forEach {
            assertEquals(it, sample.stateFor(it))
        }
    }

    @Test fun `pins require exact current signer set and catalogued package`() {
        val definition = NetworkClientCatalog.entries.first { it.releaseCertificateSha256 != null }
        val pin = requireNotNull(definition.releaseCertificateSha256)
        assertEquals(ClientIdentity.SIGNATURE_VERIFIED, definition.verifyCurrentSigners(setOf(pin)))
        assertEquals(ClientIdentity.IDENTITY_UNVERIFIED, definition.verifyCurrentSigners(setOf(pin, "other")))
        assertEquals(ClientIdentity.IDENTITY_UNVERIFIED, definition.verifyCurrentSigners(emptySet()))
        assertEquals(ClientIdentity.IDENTITY_UNVERIFIED, definition.copy(releaseCertificateSha256 = null).verifyCurrentSigners(setOf(pin)))
        assertEquals(NetworkClientCatalog.entries.size, NetworkClientCatalog.entries.map { it.packageName }.distinct().size)
    }

    @Test fun `query failures survive ready stage in the SDK status`() {
        val failed = NetworkRiskReport(NetworkRiskStage.READY, network = window(SampleConsistency.REPEATED).copy(
            snapshot = NetworkSnapshot(
                NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE),
                NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE),
                NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE),
                NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE),
            ),
        ))
        assertEquals(InfoKind.ERROR, failed.toDetectorStatus().infoKind)
    }

    @Test fun `nested network JVM signing and deployment errors reach the headline`() {
        val base = NetworkRiskReport(NetworkRiskStage.READY, network = window(SampleConsistency.REPEATED))
        val sample = requireNotNull(base.network)
        val network = VisibleNetwork(1, NetworkObservation.observed(setOf(NetworkTransport.WIFI)),
            NetworkObservation.unavailable(ProbeFailure.DISAPPEARED))
        val failedTransports = network.copy(
            transports = NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE), link = NetworkObservation.absent())
        fun withNetwork(value: VisibleNetwork) = base.copy(network = sample.copy(snapshot =
            sample.snapshot.copy(visibleNetworks = NetworkObservation.observed(listOf(value)))))
        val cases = listOf(
            withNetwork(network),
            withNetwork(failedTransports),
            base.copy(network = sample.copy(snapshot = sample.snapshot.copy(proxySources = ProxySourceCheck(
                NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE), ProxySourceComparison.SOURCE_UNAVAILABLE)))),
            base.copy(clients = NetworkClientInventory(InstalledPackageVisibility.UNKNOWN, ObservationState.UNAVAILABLE, emptyList())),
            base.copy(modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK,
                NetworkObservation(ObservationState.INCONCLUSIVE, failure = ProbeFailure.INVALID_METADATA)))),
        )
        cases.forEach { assertEquals(InfoKind.ERROR, it.toDetectorStatus().infoKind) }
    }

    @Test fun `coverage loss and changing samples are not execution errors`() {
        val limited = NetworkObservation<Long>(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED)
        val sample = window(SampleConsistency.CHANGED)
        val report = NetworkRiskReport(NetworkRiskStage.READY,
            network = sample.copy(snapshot = sample.snapshot.copy(defaultNetwork = limited,
                proxySources = ProxySourceCheck(NetworkObservation(ObservationState.INCONCLUSIVE), ProxySourceComparison.SOURCE_UNAVAILABLE))),
            modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK,
                NetworkObservation(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED))))
        assertEquals(InfoKind.SUPPORT, report.toDetectorStatus().infoKind)
        assertEquals(InfoKind.SUPPORT, NetworkRiskReport.loading().toDetectorStatus().infoKind)
    }

    @Test fun `every observed VPN and proxy source independently warns only in repeated samples`() {
        val base = window(SampleConsistency.REPEATED)
        val link = LinkContext(null, emptyList(), null, false, false, 0)
        val network = VisibleNetwork(1, NetworkObservation.observed(setOf(NetworkTransport.WIFI)), NetworkObservation.observed(link))
        val proxy = ProxyConfiguration(ProxyKind.STATIC, 8080, 0)
        val vpnNetwork = network.copy(transports = NetworkObservation.observed(setOf(NetworkTransport.VPN)))
        val proxiedNetwork = network.copy(link = NetworkObservation.observed(link.copy(proxy = proxy)))
        val snapshots = listOf(
            base.snapshot.copy(visibleNetworks = NetworkObservation.observed(listOf(vpnNetwork))),
            base.snapshot.copy(defaultProxy = NetworkObservation.observed(proxy)),
            base.snapshot.copy(defaultProxy = NetworkObservation.observed(ProxyConfiguration(ProxyKind.PAC, -1, 0))),
            base.snapshot.copy(proxySources = ProxySourceCheck(NetworkObservation.observed(8080), ProxySourceComparison.DIFFERENT)),
            base.snapshot.copy(visibleNetworks = NetworkObservation.observed(listOf(proxiedNetwork))),
        )
        snapshots.forEach { snapshot ->
            val report = NetworkRiskReport(NetworkRiskStage.READY, network = base.copy(snapshot = snapshot))
            assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
            assertEquals(DetectionSeverity.INFO, report.copy(network = base.copy(snapshot = snapshot,
                consistency = SampleConsistency.CHANGED)).toDetectorStatus().severity)
        }
    }

    @Test fun `client package warning survives signing errors and changing networks`() {
        ClientIdentity.entries.forEach { identity ->
            val report = NetworkRiskReport(NetworkRiskStage.READY, network = window(SampleConsistency.CHANGED),
                clients = NetworkClientInventory(InstalledPackageVisibility.RESTRICTED, ObservationState.OBSERVED,
                    listOf(NetworkClientEvidence("test.client", "Test", ObservationState.OBSERVED, identity,
                        signingFailure = ProbeFailure.PLATFORM_FAILURE))))
            assertEquals(DetectorStatus.warning(), report.toDetectorStatus())
            assertTrue(report.hasProbeErrors())
        }
    }

    @Test fun `limited or inconclusive signals and successful empty inventory never warn`() {
        ObservationState.entries.filter { it != ObservationState.OBSERVED }.forEach { state ->
            val report = NetworkRiskReport(NetworkRiskStage.READY,
                network = window(SampleConsistency.REPEATED).copy(snapshot = NetworkSnapshot(
                    NetworkObservation.observed(1), NetworkObservation.observed(1), NetworkObservation(state),
                    NetworkObservation.observed(emptyList()), ProxySourceCheck(NetworkObservation(state), ProxySourceComparison.SOURCE_UNAVAILABLE))),
                clients = NetworkClientInventory(InstalledPackageVisibility.RESTRICTED, ObservationState.OBSERVED,
                    listOf(NetworkClientEvidence("test.client", "Test", state))),
                modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK, NetworkObservation(state))))
            assertEquals(DetectionSeverity.INFO, report.toDetectorStatus().severity)
        }
    }

    @Test fun `loading and failed stages do not promote retained observations`() {
        val report = NetworkRiskReport(NetworkRiskStage.READY,
            modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK, NetworkObservation.observed("v5.1"))))
        assertEquals(DetectionSeverity.INFO, report.copy(stage = NetworkRiskStage.LOADING).toDetectorStatus().severity)
        assertEquals(InfoKind.ERROR, report.copy(stage = NetworkRiskStage.FAILED).toDetectorStatus().infoKind)
    }

    private fun window(consistency: SampleConsistency) = NetworkSampleWindow(
        NetworkSnapshot(NetworkObservation.observed(1), NetworkObservation.absent(),
            NetworkObservation.absent(), NetworkObservation.observed(emptyList())),
        consistency, 100, 2, 1,
    )
}
