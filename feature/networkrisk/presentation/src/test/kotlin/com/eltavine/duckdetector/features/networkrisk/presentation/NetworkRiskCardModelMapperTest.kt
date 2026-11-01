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

package com.eltavine.duckdetector.features.networkrisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectionSeverity
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.core.report.ReportBlock
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.features.networkrisk.domain.*
import org.junit.Assert.*
import org.junit.Test

class NetworkRiskCardModelMapperTest {
    private val mapper = NetworkRiskCardModelMapper()

    @Test fun `only installed stopped excluded and direct-rule scenarios cannot imply active traffic`() {
        // These states are indistinguishable to passive package and configuration observations.
        listOf(false, true).forEach { vpn ->
            listOf(false, true).forEach { proxy ->
                val model = mapper.map(report(vpn = vpn, proxy = proxy, client = true))
                assertEquals(DetectionSeverity.WARNING, model.status.severity)
                assertTrue(model.verdict.contains("Network risk indicators observed"))
                val rows = model.sections.flatMap { it.rows }
                assertTrue(rows.filter { it.label.endsWith("traffic effect") }.all { it.value == "Unavailable" })
                assertTrue(rows.filter { it.label.endsWith("service response") }.all { it.value == "Unavailable" })
                assertTrue(rows.any { it.detail?.contains("Installed does not mean running") == true })
                assertEquals(model.status.severity, model.toDetectorReport().severity)
                assertEquals(model.verdict, model.toDetectorReport().verdict)
            }
        }
    }

    @Test fun `Private DNS alone and ordinary network context stay informational`() {
        val model = mapper.map(report(vpn = false, proxy = false))
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertEquals("Not observed", model.headerFacts[0].value)
        assertEquals("Not observed", model.headerFacts[1].value)
        assertTrue(model.sections.flatMap { it.rows }.any { it.label.endsWith("Private DNS") && it.value == "Observed" })
    }

    @Test fun `export strips interface names and network handles without parsing text`() {
        val base = report()
        val sample = requireNotNull(base.network)
        val model = mapper.map(base.copy(network = sample.copy(snapshot = sample.snapshot.copy(
            proxySources = ProxySourceCheck(NetworkObservation.observed(7890), ProxySourceComparison.ALIGNED)))))
        assertTrue(model.sections.flatMap { it.rows }.any { it.value.contains("private_tun_name") })
        val exported = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>().flatMap { it.rows }
            .joinToString { "${it.label} ${it.value} ${it.detail}" }
        assertFalse(exported.contains("private_tun_name"))
        assertFalse(exported.contains("123456789"))
        assertFalse(exported.contains("local handle"))
    }

    @Test fun `network switching and restricted inventory do not produce clean or contradictory claims`() {
        val model = mapper.map(report().copy(network = requireNotNull(report().network).copy(consistency = SampleConsistency.CHANGED)))
        assertEquals("Network changed during scan", model.verdict)
        assertEquals("Inconclusive", model.headerFacts.first().value)
        val clients = model.sections.first { it.key == "clients" }.rows
        assertTrue(clients.first().detail!!.contains("Other users and work profiles are not queried"))
        assertEquals("Not observed", clients.last().value)
    }

    @Test fun `permission failures and platform failures retain different meanings`() {
        val base = report(vpn = false, proxy = false)
        val sample = requireNotNull(base.network)
        val denied = NetworkObservation<Long>(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED)
        val model = mapper.map(base.copy(network = sample.copy(snapshot = sample.snapshot.copy(defaultNetwork = denied))))
        assertEquals("Permission limited", model.sections.first().rows.first().value)
        assertEquals(InfoKind.SUPPORT, model.sections.first().rows.first().status.infoKind)
        assertEquals(InfoKind.ERROR, mapper.map(NetworkRiskReport.failed("failure")).status.infoKind)
    }

    @Test fun `query errors and disabled active coverage are independently reported`() {
        val base = report(vpn = false, proxy = false)
        val sample = requireNotNull(base.network)
        val failed = NetworkObservation<Long>(ObservationState.UNAVAILABLE, failure = ProbeFailure.PLATFORM_FAILURE)
        val model = mapper.map(base.copy(network = sample.copy(snapshot = sample.snapshot.copy(defaultNetwork = failed))))
        assertEquals(InfoKind.ERROR, model.sections.first().rows.first().status.infoKind)
        assertTrue(model.sections.first { it.key == "scan" }.rows.filter { it.label == "Active protocol / DNS / egress tests" }
            .all { it.status.infoKind == InfoKind.SUPPORT })
    }

    @Test fun `offline blocked and no process binding remain separate scoped rows`() {
        val base = report()
        val sample = requireNotNull(base.network)
        val model = mapper.map(base.copy(network = sample.copy(snapshot = sample.snapshot.copy(
            defaultNetwork = NetworkObservation.absent(), boundNetwork = NetworkObservation.absent(),
            visibleNetworks = NetworkObservation.observed(emptyList()), defaultProxy = NetworkObservation.absent(),
        ))))
        assertEquals("Not observed", model.sections.first().rows.first().value)
        assertTrue(model.sections.first().rows.first().detail!!.contains("blocked"))
        assertEquals(DetectionSeverity.INFO, model.status.severity)
    }

    @Test fun `source differences and network changes are informational and PAC is not compared`() {
        val base = report()
        val sample = requireNotNull(base.network)
        ProxySourceComparison.entries.forEach { comparison ->
            val sources = ProxySourceCheck(NetworkObservation.observed(7890), comparison)
            val model = mapper.map(base.copy(network = sample.copy(snapshot = sample.snapshot.copy(proxySources = sources))))
            assertEquals(DetectionSeverity.WARNING, model.status.severity)
            val crossCheck = model.sections.flatMap { it.rows }.single { it.label == "Proxy source cross-check" }
            assertEquals(InfoKind.SUPPORT, crossCheck.status.infoKind)
            if (comparison == ProxySourceComparison.DIFFERENT) assertEquals("Inconclusive: views differ", crossCheck.value)
            if (comparison == ProxySourceComparison.PAC_NOT_COMPARABLE) assertEquals("Not comparable: PAC", crossCheck.value)
            val changed = mapper.map(base.copy(network = sample.copy(consistency = SampleConsistency.CHANGED,
                snapshot = sample.snapshot.copy(proxySources = sources))))
            assertEquals("Inconclusive", changed.sections.flatMap { it.rows }.single { it.label == "Proxy source cross-check" }.value)
        }
    }

    @Test fun `probe errors produce an incomplete headline and retain exported failure detail`() {
        val base = report(vpn = false, proxy = false)
        val sample = requireNotNull(base.network)
        val failed = NetworkObservation<Long>(ObservationState.UNAVAILABLE, failure = ProbeFailure.PLATFORM_FAILURE)
        val model = mapper.map(base.copy(network = sample.copy(snapshot = sample.snapshot.copy(defaultNetwork = failed))))
        assertEquals(InfoKind.ERROR, model.status.infoKind)
        assertEquals("Network context incomplete", model.verdict)
        assertTrue(model.summary.contains("Some probes failed"))
        assertEquals(model.verdict, model.toDetectorReport().verdict)
        val rows = model.toDetectorReport().blocks.filterIsInstance<ReportBlock.Rows>().flatMap { it.rows }
        assertTrue(rows.any { it.value == "Unavailable" && it.detail.orEmpty().contains("Platform query or read failed") })
    }

    @Test fun `VPN and proxy warnings reach matching rows but ordinary context stays informational`() {
        val model = mapper.map(report())
        assertEquals(DetectionSeverity.WARNING, model.status.severity)
        assertEquals(DetectionSeverity.WARNING, model.headerFacts[0].status.severity)
        assertEquals(DetectionSeverity.WARNING, model.headerFacts[1].status.severity)
        val rows = model.sections.flatMap { it.rows }
        listOf("Network 1 transports", "Default HTTP proxy", "Network 1 link proxy / PAC").forEach { label ->
            assertEquals(label, DetectionSeverity.WARNING, rows.single { it.label == label }.status.severity)
        }
        listOf("Caller default network", "Process binding", "Visible networks", "Network 1 interface / routes",
            "Network 1 Private DNS", "Package visibility", "Sample consistency", "Export privacy").forEach { label ->
            assertEquals(label, DetectionSeverity.INFO, rows.single { it.label == label }.status.severity)
        }
    }

    @Test fun `JVM proxy and deployment traces independently warn in App and export`() {
        val base = report(vpn = false, proxy = false)
        val sample = requireNotNull(base.network)
        val reports = listOf(
            base.copy(network = sample.copy(snapshot = sample.snapshot.copy(proxySources =
                ProxySourceCheck(NetworkObservation.observed(7890), ProxySourceComparison.DIFFERENT)))),
            base.copy(modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX_FOR_ROOT, NetworkObservation.observed("v1.10.2")))),
            base.copy(clients = requireNotNull(base.clients).copy(clients = listOf(
                NetworkClientEvidence("moe.nb4a", "NekoBox", ObservationState.OBSERVED, signingFailure = ProbeFailure.PLATFORM_FAILURE)))),
        )
        val labels = listOf("JVM HTTP proxy", "Box for Root deployment trace", "NekoBox")
        reports.zip(labels).forEach { (report, label) ->
            val model = mapper.map(report)
            assertEquals(DetectionSeverity.WARNING, model.status.severity)
            assertEquals(DetectionSeverity.WARNING, model.sections.flatMap { it.rows }.single { it.label == label }.status.severity)
            assertEquals(model.status.severity, model.toDetectorReport().severity)
            assertEquals(model.verdict, model.toDetectorReport().verdict)
        }
        assertTrue(mapper.map(reports.last()).summary.contains("Some probes failed"))
    }

    @Test fun `changed samples suppress network warnings while independent package evidence survives`() {
        val base = report()
        val changed = base.copy(network = requireNotNull(base.network).copy(consistency = SampleConsistency.CHANGED))
        val model = mapper.map(changed)
        assertEquals(DetectionSeverity.INFO, model.status.severity)
        assertTrue(model.headerFacts.take(2).all { it.status.severity == DetectionSeverity.INFO })
        assertTrue(model.sections.filter { it.key == "networks" || it.key == "proxy" }.flatMap { it.rows }
            .all { it.status.severity == DetectionSeverity.INFO })
        val packageModel = mapper.map(changed.copy(clients = requireNotNull(report(client = true).clients)))
        assertEquals(DetectionSeverity.WARNING, packageModel.status.severity)
        assertEquals(DetectionSeverity.WARNING, packageModel.headerFacts[2].status.severity)
        assertTrue(packageModel.verdict.contains("network changed"))
    }

    private fun report(vpn: Boolean = true, proxy: Boolean = true, client: Boolean = false): NetworkRiskReport {
        val link = LinkContext("private_tun_name", listOf(VisibleRoute(AddressFamily.IPV6, 0, true, false)),
            if (proxy) ProxyConfiguration(ProxyKind.PAC, -1, 0) else null, true, true, 1)
        return NetworkRiskReport(NetworkRiskStage.READY,
            network = NetworkSampleWindow(NetworkSnapshot(NetworkObservation.observed(123456789L), NetworkObservation.absent(),
                if (proxy) NetworkObservation.observed(ProxyConfiguration(ProxyKind.STATIC, 8080, 0)) else NetworkObservation.absent(),
                NetworkObservation.observed(listOf(VisibleNetwork(123456789L,
                    NetworkObservation.observed(if (vpn) setOf(NetworkTransport.VPN) else setOf(NetworkTransport.WIFI)), NetworkObservation.observed(link))))),
                SampleConsistency.REPEATED, 100, 2, 1),
            clients = NetworkClientInventory(InstalledPackageVisibility.RESTRICTED, ObservationState.OBSERVED,
                listOf(NetworkClientEvidence("moe.nb4a", "NekoBox", if (client) ObservationState.OBSERVED else ObservationState.NOT_OBSERVED), NetworkClientEvidence("com.follow.clash", "FlClash", ObservationState.NOT_OBSERVED))),
            modules = listOf(ProxyModuleEvidence(ProxyDeployment.BOX4MAGISK, NetworkObservation(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED))),
        )
    }
}
