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

package com.eltavine.duckdetector.features.tee.data.report

import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceItem
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSection
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceSectionKind
import com.eltavine.duckdetector.features.tee.domain.TeeEvidenceTopic
import com.eltavine.duckdetector.features.tee.domain.TeePatchState
import com.eltavine.duckdetector.features.tee.domain.TeeSignalLevel

internal fun buildSections(
    artifacts: TeeScanArtifacts,
    patchState: TeePatchState,
    policyHardIndicators: List<TeeEvidenceItem>,
    policySoftIndicators: List<TeeEvidenceItem>,
    supplementaryIndicators: List<TeeEvidenceItem>,
): List<TeeEvidenceSection> {
    return listOf(
        TeeEvidenceSection(
            kind = TeeEvidenceSectionKind.TRUST,
            items = trustItems(artifacts),
        ),
        TeeEvidenceSection(
            kind = TeeEvidenceSectionKind.ATTESTATION,
            items = attestationItems(artifacts),
        ),
        TeeEvidenceSection(
            kind = TeeEvidenceSectionKind.CHECKS,
            items = checkItems(artifacts, policyHardIndicators, policySoftIndicators, supplementaryIndicators),
        ),
    )
}

private fun trustItems(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> = buildList {
    add(
        fact(
            "Local chain",
            if (artifacts.trust.chainSignatureValid) "Verified" else "Failed",
            if (artifacts.trust.chainSignatureValid) TeeSignalLevel.PASS else TeeSignalLevel.FAIL
        )
    )
    add(
        fact(
            "Trust root",
            trustRootLabel(artifacts.trust.trustRoot),
            trustLevel(artifacts),
            topic = TeeEvidenceTopic.TRUST_ROOT,
        )
    )
    add(
        fact(
            "Chain layout",
            chainLayoutValue(artifacts),
            chainLayoutLevel(artifacts)
        )
    )
    add(fact("RKP", rkpValue(artifacts), rkpDisplayLevel(artifacts), topic = TeeEvidenceTopic.RKP))
    if (artifacts.rkp.provisioned) {
        add(fact(
            "RKP build metadata",
            rkpBuildMetadataValue(artifacts.rkp),
            TeeSignalLevel.INFO,
            topic = TeeEvidenceTopic.RKP,
        ))
    }
    add(fact("CRL", crlValue(artifacts), crlSignalLevel(artifacts), topic = TeeEvidenceTopic.CRL))
    add(
        fact(
            "Root fingerprint",
            shortFingerprint(artifacts.trust.rootFingerprint),
            TeeSignalLevel.INFO
        )
    )
}

private fun attestationItems(artifacts: TeeScanArtifacts): List<TeeEvidenceItem> = buildList {
    add(
        fact(
            "Tier",
            tierValue(artifacts),
            tierLevel(effectiveTier(artifacts))
        )
    )
    add(fact("Versions", versionsValue(artifacts.snapshot), TeeSignalLevel.INFO))
    add(
        fact(
            "Challenge",
            challengeValue(artifacts.snapshot),
            challengeLevel(artifacts.snapshot)
        )
    )
    add(
        fact(
            "Verified boot",
            verifiedBootValue(artifacts.snapshot),
            verifiedBootLevel(artifacts.snapshot),
            topic = TeeEvidenceTopic.VERIFIED_BOOT,
        )
    )
    add(
        fact(
            "Boot consistency",
            bootConsistencyValue(artifacts),
            bootSignalLevel(artifacts),
            topic = TeeEvidenceTopic.BOOT_CONSISTENCY,
        )
    )
    add(
        fact(
            "Device IDs",
            deviceInfoValue(artifacts.snapshot),
            deviceInfoLevel(artifacts.snapshot),
            topic = TeeEvidenceTopic.DEVICE_IDS,
        )
    )
    add(
        fact(
            "Key properties",
            keyPropertiesValue(artifacts.snapshot),
            TeeSignalLevel.INFO
        )
    )
    add(fact("User auth", authStateValue(artifacts.snapshot), TeeSignalLevel.INFO, topic = TeeEvidenceTopic.USER_AUTH))
    add(
        fact(
            "Application",
            applicationInfoValue(artifacts.snapshot),
            TeeSignalLevel.INFO,
            topic = TeeEvidenceTopic.APPLICATION,
        )
    )
}
