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

package com.eltavine.duckdetector.features.rootmanagers.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Policy
import com.eltavine.duckdetector.core.ui.detector.ConsentCard
import com.eltavine.duckdetector.core.ui.detector.ConsentPrompt
import com.eltavine.duckdetector.core.ui.detector.ConsentSetting
import com.eltavine.duckdetector.features.rootmanagers.detector.RootManagersInstallerCanaryConsent

internal val installerCanaryConsentCard = ConsentCard(
    consent = RootManagersInstallerCanaryConsent,
    prompt = ConsentPrompt(
        icon = Icons.Rounded.Policy,
        title = R.string.installer_canary_title,
        headline = R.string.installer_canary_headline,
        detail = R.string.installer_canary_detail,
        allowLabel = R.string.installer_canary_allow,
        declineLabel = R.string.installer_canary_decline,
        grantedHeadline = R.string.installer_canary_granted,
        grantedDetail = R.string.installer_canary_detail,
        declinedStatus = R.string.installer_canary_disabled,
        declinedHeadline = R.string.installer_canary_decline,
        declinedDetail = R.string.installer_canary_declined_detail,
    ),
    setting = ConsentSetting(
        icon = Icons.Rounded.Policy,
        title = R.string.installer_canary_title,
        summary = R.string.installer_canary_headline,
        footer = R.string.installer_canary_detail,
    ),
)
