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

package com.eltavine.duckdetector.features.locationrisk.presentation

import com.eltavine.duckdetector.core.evidence.DetectorStatus
import com.eltavine.duckdetector.core.evidence.InfoKind
import com.eltavine.duckdetector.features.locationrisk.domain.*
import com.eltavine.duckdetector.features.locationrisk.presentation.model.*

class LocationRiskCardModelMapper {
    fun map(report: LocationRiskReport): LocationRiskCardModel {
        val mismatches = report.contracts.count { it.state == LocationState.OBSERVED }
        val mockSamples = report.cache?.samples.orEmpty().count { it.hasMockEvidence() }
        val ready = report.stage == LocationRiskStage.READY
        val partialContracts = report.contracts.any {
            it.state == LocationState.UNAVAILABLE || it.state == LocationState.PERMISSION_LIMITED || it.state == LocationState.INCONCLUSIVE
        }
        return LocationRiskCardModel(
            title = "Location Risk",
            subtitle = "Location API contracts and optional cached mock metadata",
            status = report.toDetectorStatus(),
            verdict = when {
                report.stage == LocationRiskStage.LOADING -> "Scanning"
                report.stage == LocationRiskStage.FAILED -> "Scan failed"
                mismatches > 0 -> "Location contract mismatch observed"
                mockSamples > 0 -> "Cached mock location observed"
                report.installedPackage?.state == LocationState.OBSERVED -> "Location reference package observed"
                partialContracts && report.contracts.any { it.state == LocationState.NOT_OBSERVED } -> "Local contracts partially evaluated"
                report.contracts.any { it.state == LocationState.NOT_OBSERVED } -> "No local contract mismatch observed"
                else -> "Local contracts not evaluated"
            },
            summary = if (report.stage == LocationRiskStage.FAILED) report.errorMessage ?: "Collection failed." else
                "Warnings highlight local contract mismatches, cached mock marks or the reference package. Cached marks can be historical or legitimate tests; package identity is unverified and installation does not establish activity. No check authenticates the real position.",
            headerFacts = listOf(
                row("Local contracts", if (!ready || report.contracts.isEmpty()) LocationState.UNAVAILABLE else
                    if (mismatches > 0) LocationState.OBSERVED else if (partialContracts) LocationState.INCONCLUSIVE else LocationState.NOT_OBSERVED,
                    "Four contracts share one framework surface; they are not independent trust sources.", warning = mismatches > 0),
                row("Cached mock marks", if (mockSamples > 0) LocationState.OBSERVED else cacheMockState(report.cache),
                    "Historical cached fixes only; false does not authenticate a position.", warning = mockSamples > 0),
                row("Reference package", report.installedPackage?.state ?: LocationState.UNAVAILABLE,
                    "Exact package name; identity unverified; installation does not establish activity.",
                    warning = report.installedPackage?.state == LocationState.OBSERVED),
                row("Cache access", report.cache?.state ?: LocationState.UNAVAILABLE,
                    "Opt-in, foreground permission, up to three cached reads; no sensor request."),
            ),
            sections = if (!ready) emptyList() else listOf(
                LocationRiskSectionModel("contracts", "App-owned Location contracts", report.contracts.map { check ->
                    row(contractLabel(check.contract), check.state,
                        "Up to two synthetic objects; no real fix. Fields: ${check.mismatches.joinToString().ifEmpty { "none" }}. ${failureDetail(check.failure)}" +
                            if (check.contract == LocationContract.MOCK_FLAG) " Public setMock requires API 31; older releases are unsupported." else "",
                        warning = check.state == LocationState.OBSERVED, failure = check.failure)
                }),
                LocationRiskSectionModel("cache", "Optional cached location context", cacheRows(report.cache)),
                LocationRiskSectionModel("package", "Reference project package", listOf(
                    row("VirtualLocation package", report.installedPackage?.state ?: LocationState.UNAVAILABLE,
                        "com.vincenthzr.locationspoofer; source revision dcbe6203; identity unverified. No upstream release signer was established; no name-based matching. Installed does not mean enabled or running.",
                        warning = report.installedPackage?.state == LocationState.OBSERVED),
                    row("Package visibility", report.installedPackage?.let { if (it.failure == null) LocationState.OBSERVED else it.state } ?: LocationState.UNAVAILABLE,
                        "${report.installedPackage?.visibility ?: "UNKNOWN"}; caller user/profile only. Not observed does not mean globally uninstalled.", failure = report.installedPackage?.failure),
                )),
                LocationRiskSectionModel("scope", "Coverage and privacy", listOf(
                    row("Observation boundary", LocationState.INCONCLUSIVE,
                        "System-service-only spoofing, selective hooks, an excluded app or coherent forged metadata can pass local checks. No GNSS, Wi-Fi, cell, IP or trajectory cross-validation; no module attribution."),
                    row("Legitimate contexts", LocationState.OBSERVED,
                        "Test providers, emulators, automation and development can mark locations as mock. No cache, a disabled location switch, old timestamps or provider differences do not prove spoofing."),
                    row("Data budget", LocationState.OBSERVED,
                        "No external endpoints or network payloads. No active fixes, listeners or background location permission. Coordinates, raw fix times, extras and history are never retained in reports or export."),
                )),
            ),
        )
    }

    private fun cacheRows(cache: CachedLocationContext?): List<LocationRiskDetailRowModel> = buildList {
        add(row("Cache collection", cache?.state ?: LocationState.UNAVAILABLE,
            "Permission: ${cache?.permission ?: LocationPermission.NONE}; location switch: ${cache?.locationEnabled ?: "unknown"}; sample start (elapsed ms): ${cache?.sampledAtElapsedMs ?: "not sampled"}. ${failureDetail(cache?.failure)}", failure = cache?.failure))
        cache?.samples.orEmpty().forEach { sample ->
            add(row("${sample.provider} mock marker", sample.state,
                "Age bucket: ${sample.age}; cached metadata only, not current service state. ${failureDetail(sample.failure)}",
                warning = sample.hasMockEvidence(), failure = sample.failure))
            if (sample.ageFailure != null || sample.mockMarked != null && (sample.age == CacheAge.FUTURE || sample.age == CacheAge.UNKNOWN || sample.age == CacheAge.STALE)) {
                add(row("${sample.provider} freshness", LocationState.INCONCLUSIVE,
                    "${sample.age}; recent means at most five minutes, a display policy rather than proof of authenticity. No cross-provider contradiction rule. ${failureDetail(sample.ageFailure)}",
                    failure = sample.ageFailure))
            }
        }
    }

    private fun cacheMockState(cache: CachedLocationContext?): LocationState = when {
        cache == null -> LocationState.UNAVAILABLE
        cache.state != LocationState.OBSERVED -> cache.state
        cache.samples.any { it.mockMarked == false } && cache.samples.any { it.mockMarked == null } -> LocationState.INCONCLUSIVE
        cache.samples.any { it.mockMarked == false } -> LocationState.NOT_OBSERVED
        else -> LocationState.UNAVAILABLE
    }

    private fun contractLabel(contract: LocationContract): String = when (contract) {
        LocationContract.VALUES -> "Setter / getter round trip"
        LocationContract.OPTIONAL_FIELDS -> "Optional field flags"
        LocationContract.RESET -> "Reset semantics"
        LocationContract.MOCK_FLAG -> "Synthetic mock flag round trip"
    }
}

private fun row(label: String, state: LocationState, detail: String, warning: Boolean = false, failure: LocationFailure? = null) = LocationRiskDetailRowModel(
    label, when (state) {
        LocationState.OBSERVED -> "Observed"
        LocationState.NOT_OBSERVED -> "Not observed"
        LocationState.UNAVAILABLE -> "Unavailable"
        LocationState.PERMISSION_LIMITED -> "Permission limited"
        LocationState.UNSUPPORTED -> "Unsupported"
        LocationState.INCONCLUSIVE -> "Inconclusive"
    }, if (warning) DetectorStatus.warning() else DetectorStatus.info(
        if (failure == LocationFailure.PLATFORM_FAILURE) InfoKind.ERROR else InfoKind.SUPPORT
    ), detail,
)

private fun failureDetail(failure: LocationFailure?): String = when (failure) {
    null -> ""
    LocationFailure.ACCESS_DENIED -> "Access denied; permission or AppOps may restrict the caller."
    LocationFailure.PLATFORM_FAILURE -> "Platform query failed; evidence unavailable."
    LocationFailure.PROVIDER_ABSENT -> "Provider absent or rejected; outside coverage."
    LocationFailure.NO_CACHE -> "No accessible cached fix; not evidence of absence."
    LocationFailure.DISABLED_BY_USER -> "Disabled by default; enable in setup or settings."
}
