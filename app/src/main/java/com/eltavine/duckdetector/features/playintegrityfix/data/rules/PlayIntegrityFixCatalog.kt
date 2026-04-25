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

package com.eltavine.duckdetector.features.playintegrityfix.data.rules

import com.eltavine.duckdetector.features.playintegrityfix.domain.PlayIntegrityFixPropertyCategory

data class PlayIntegrityFixPropertyRule(
    val property: String,
    val label: String,
    val category: PlayIntegrityFixPropertyCategory,
)

object PlayIntegrityFixCatalog {

    val rules: List<PlayIntegrityFixPropertyRule> = listOf(
        PlayIntegrityFixPropertyRule(
            "persist.sys.spoof.gms",
            "GMS spoof",
            PlayIntegrityFixPropertyCategory.CONTROL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks.disable.gms",
            "GMS hook toggle",
            PlayIntegrityFixPropertyCategory.CONTROL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_ID",
            "Hook profile ID",
            PlayIntegrityFixPropertyCategory.CONTROL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_DEVICE_INIT",
            "Device init hook",
            PlayIntegrityFixPropertyCategory.CONTROL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pixelprops.pi",
            "Play Integrity pixel props",
            PlayIntegrityFixPropertyCategory.PIXEL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pixelprops.gms",
            "GMS pixel props",
            PlayIntegrityFixPropertyCategory.PIXEL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pixelprops.gapps",
            "GApps pixel props",
            PlayIntegrityFixPropertyCategory.PIXEL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pixelprops.google",
            "Google pixel props",
            PlayIntegrityFixPropertyCategory.PIXEL
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_BRAND",
            "Spoofed brand",
            PlayIntegrityFixPropertyCategory.DEVICE
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_MODEL",
            "Spoofed model",
            PlayIntegrityFixPropertyCategory.DEVICE
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_DEVICE",
            "Spoofed device",
            PlayIntegrityFixPropertyCategory.DEVICE
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_PRODUCT",
            "Spoofed product",
            PlayIntegrityFixPropertyCategory.DEVICE
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_MANUFACTURE",
            "Spoofed manufacture",
            PlayIntegrityFixPropertyCategory.DEVICE
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_MANUFACTURER",
            "Spoofed manufacturer",
            PlayIntegrityFixPropertyCategory.DEVICE
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_RELEASE",
            "Spoofed Android release",
            PlayIntegrityFixPropertyCategory.SECURITY
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_SDK_INT",
            "Spoofed SDK level",
            PlayIntegrityFixPropertyCategory.SECURITY
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_FINGERPRINT",
            "Spoofed fingerprint",
            PlayIntegrityFixPropertyCategory.SECURITY
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_SECURITY_PA",
            "Spoofed security patch",
            PlayIntegrityFixPropertyCategory.SECURITY
        ),
        PlayIntegrityFixPropertyRule(
            "persist.sys.pihooks_SECURITY_PATCH",
            "Spoofed security patch",
            PlayIntegrityFixPropertyCategory.SECURITY
        ),
    )
}
