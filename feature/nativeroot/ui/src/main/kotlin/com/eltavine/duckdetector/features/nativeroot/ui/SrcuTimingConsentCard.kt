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

package com.eltavine.duckdetector.features.nativeroot.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Timer
import com.eltavine.duckdetector.core.ui.detector.ConsentCard
import com.eltavine.duckdetector.core.ui.detector.ConsentPrompt
import com.eltavine.duckdetector.core.ui.detector.ConsentSetting
import com.eltavine.duckdetector.features.nativeroot.detector.NativeRootSrcuTimingConsent

internal val srcuTimingConsentCard = ConsentCard(
    consent = NativeRootSrcuTimingConsent,
    prompt = ConsentPrompt(
        icon = Icons.Rounded.Timer,
        title = R.string.srcu_timing_title,
        headline = R.string.srcu_timing_headline,
        detail = R.string.srcu_timing_detail,
        allowLabel = R.string.srcu_timing_allow,
        declineLabel = R.string.srcu_timing_decline,
        grantedHeadline = R.string.srcu_timing_granted,
        grantedDetail = R.string.srcu_timing_detail,
        declinedStatus = R.string.srcu_timing_disabled,
        declinedHeadline = R.string.srcu_timing_decline,
        declinedDetail = R.string.srcu_timing_declined_detail,
    ),
    setting = ConsentSetting(
        icon = Icons.Rounded.Timer,
        title = R.string.srcu_timing_title,
        summary = R.string.srcu_timing_headline,
        footer = R.string.srcu_timing_detail,
    ),
)
