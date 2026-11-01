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

package com.eltavine.duckdetector.core.ui.detector

import androidx.annotation.StringRes
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.vector.ImageVector
import com.eltavine.duckdetector.core.detector.DetectorConsent

/**
 * How the application asks for one [DetectorConsent]: as a card on the startup policy screen before
 * the first scan, and as a setting afterwards. The detector's ui module supplies the icons and words,
 * so the application shows every consent without naming the detector that asks for it.
 */
@Immutable
public class ConsentCard(
    public val consent: DetectorConsent,
    public val prompt: ConsentPrompt,
    public val setting: ConsentSetting,
    /** Requested only after explicit opt-in; denial never changes the recorded consent. */
    public val runtimePermissions: List<String> = emptyList(),
)

/** The consent's card on the startup policy screen, for each decision the user can have made. */
@Immutable
public class ConsentPrompt(
    public val icon: ImageVector,
    @param:StringRes public val title: Int,
    @param:StringRes public val headline: Int,
    @param:StringRes public val detail: Int,
    @param:StringRes public val allowLabel: Int,
    @param:StringRes public val declineLabel: Int,
    @param:StringRes public val grantedHeadline: Int,
    @param:StringRes public val grantedDetail: Int,
    @param:StringRes public val declinedStatus: Int,
    @param:StringRes public val declinedHeadline: Int,
    @param:StringRes public val declinedDetail: Int,
)

/** The consent's switch in settings; it is on only while the consent is granted. */
@Immutable
public class ConsentSetting(
    public val icon: ImageVector,
    @param:StringRes public val title: Int,
    @param:StringRes public val summary: Int,
    @param:StringRes public val footer: Int,
)
