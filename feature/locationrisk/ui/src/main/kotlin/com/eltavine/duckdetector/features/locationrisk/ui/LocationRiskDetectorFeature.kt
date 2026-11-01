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

package com.eltavine.duckdetector.features.locationrisk.ui

import android.Manifest
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.LocationOn
import com.eltavine.duckdetector.core.ui.detector.*
import com.eltavine.duckdetector.features.locationrisk.detector.LocationRiskDetector
import com.eltavine.duckdetector.features.locationrisk.detector.LocationCacheConsent
import com.eltavine.duckdetector.features.locationrisk.ui.card.LocationRiskDetectorCard

val detectorFeature: DetectorFeature = CardDetectorFeature(
    LocationRiskDetector,
    consentCards = listOf(locationCacheConsentCard()),
) { model -> LocationRiskDetectorCard(model = model) }

private fun locationCacheConsentCard() = ConsentCard(
    consent = LocationCacheConsent,
    runtimePermissions = listOf(Manifest.permission.ACCESS_COARSE_LOCATION),
    prompt = ConsentPrompt(
        icon = Icons.Rounded.LocationOn,
        title = R.string.location_cache_title,
        headline = R.string.location_cache_headline,
        detail = R.string.location_cache_detail,
        allowLabel = R.string.location_cache_allow,
        declineLabel = R.string.location_cache_decline,
        grantedHeadline = R.string.location_cache_granted_headline,
        grantedDetail = R.string.location_cache_granted_detail,
        declinedStatus = R.string.location_cache_declined_status,
        declinedHeadline = R.string.location_cache_declined_headline,
        declinedDetail = R.string.location_cache_declined_detail,
    ),
    setting = ConsentSetting(
        icon = Icons.Rounded.LocationOn,
        title = R.string.location_cache_title,
        summary = R.string.location_cache_setting_summary,
        footer = R.string.location_cache_detail,
    ),
)
