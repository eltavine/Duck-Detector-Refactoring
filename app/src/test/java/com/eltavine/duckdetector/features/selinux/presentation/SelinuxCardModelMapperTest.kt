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

package com.eltavine.duckdetector.features.selinux.presentation

import com.eltavine.duckdetector.core.ui.model.DetectorStatus
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditEvidence
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityAnalysis
import com.eltavine.duckdetector.features.selinux.domain.SelinuxAuditIntegrityState
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxCardModelMapperTest {

    private val mapper = SelinuxCardModelMapper()

    @Test
    fun `audit exposure maps to warning instead of root claim`() {
        val model = mapper.map(
            SelinuxReport(
                stage = SelinuxStage.READY,
                mode = SelinuxMode.ENFORCING,
                resolvedStatusLabel = "Enforcing",
                filesystemMounted = true,
                paradoxDetected = false,
                methods = emptyList(),
                processContext = "u:r:untrusted_app:s0:c1,c2",
                contextType = "untrusted_app",
                policyAnalysis = null,
                auditIntegrity = SelinuxAuditIntegrityAnalysis(
                    state = SelinuxAuditIntegrityState.EXPOSED,
                    residueHits = emptyList(),
                    runtimeHits = emptyList(),
                    sideChannelHits = listOf(
                        SelinuxAuditEvidence(
                            label = "AVC denial leak",
                            value = "comm=su",
                            detail = "avc: denied ...",
                        ),
                    ),
                    suspiciousActorHits = listOf(
                        SelinuxAuditEvidence(
                            label = "su-related AVC",
                            value = "comm=su",
                            detail = "avc: denied ...",
                        ),
                    ),
                    logcatChecked = true,
                    directProbeUsed = true,
                    notes = listOf(
                        "A direct libselinux callback probe and app-visible auditd event logs both observed the same nonce-tagged AVC denial. Treat this as audit side-channel leakage, not direct root-process proof.",
                    ),
                ),
                androidVersion = "15",
                apiLevel = 35,
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with audit exposure", model.verdict)
        assertTrue(model.auditRows.any { it.label == "AVC side-channel" && it.value == "1 hit(s)" })
        assertTrue(model.auditRows.any { it.label == "su-related AVC" && it.value == "1 hit(s)" })
        assertTrue(model.auditNotes.any { it.text.contains("not direct root-process proof") })
    }

    @Test
    fun `inconclusive audit scan stays support instead of clear`() {
        val model = mapper.map(
            SelinuxReport(
                stage = SelinuxStage.READY,
                mode = SelinuxMode.ENFORCING,
                resolvedStatusLabel = "Enforcing",
                filesystemMounted = true,
                paradoxDetected = false,
                methods = emptyList(),
                processContext = "u:r:untrusted_app:s0:c1,c2",
                contextType = "untrusted_app",
                policyAnalysis = null,
                auditIntegrity = SelinuxAuditIntegrityAnalysis(
                    state = SelinuxAuditIntegrityState.INCONCLUSIVE,
                    residueHits = emptyList(),
                    runtimeHits = emptyList(),
                    sideChannelHits = emptyList(),
                    suspiciousActorHits = emptyList(),
                    logcatChecked = true,
                    directProbeUsed = true,
                    notes = listOf("AOSP does not guarantee that every device emits or exposes matching audit events to app-visible log readers, so this remains non-proving."),
                ),
                androidVersion = "16",
                apiLevel = 36,
            ),
        )

        val runtimeRow = model.auditRows.first { it.label == "Runtime markers" }
        val avcRow = model.auditRows.first { it.label == "AVC side-channel" }
        val suAvcRow = model.auditRows.first { it.label == "su-related AVC" }

        assertEquals("Inconclusive", model.auditRows.first { it.label == "Surface" }.value)
        assertEquals("Not observed", runtimeRow.value)
        assertEquals("Not observed", avcRow.value)
        assertEquals("Not observed", suAvcRow.value)
        assertFalse(runtimeRow.status == DetectorStatus.allClear())
        assertFalse(avcRow.status == DetectorStatus.allClear())
        assertTrue(model.summary.contains("non-proving"))
    }
}
