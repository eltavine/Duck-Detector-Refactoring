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
import com.eltavine.duckdetector.features.selinux.domain.SelinuxCheckResult
import com.eltavine.duckdetector.features.selinux.domain.SelinuxMode
import com.eltavine.duckdetector.features.selinux.domain.SelinuxReport
import com.eltavine.duckdetector.features.selinux.domain.SelinuxStage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SelinuxCardModelMapperDirtyPolicyRulesTest {

    private val mapper = SelinuxCardModelMapper()

    @Test
    fun `dirty sepolicy rule rows stay visible with per-rule statuses`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = "Dirty sepolicy rule: system_server execmem",
                    status = "Allowed",
                    isSecure = false,
                    permissionDenied = false,
                    details = "Observed edge: system_server -> system_server:process execmem. This should stay denied on stock policy because executable system_server memory is supporting dirty-policy evidence. The access oracle reported this edge as allowed.",
                ),
                SelinuxCheckResult(
                    method = "Dirty sepolicy rule: untrusted_app -> ksu_file read",
                    status = "Denied",
                    isSecure = true,
                    permissionDenied = false,
                    details = "Observed edge: untrusted_app -> ksu_file:file read. This should stay denied on stock policy because ordinary apps should not read KernelSU-labeled files. The access oracle reported this edge as denied.",
                ),
                SelinuxCheckResult(
                    method = "Dirty sepolicy rule: shell -> su transition",
                    status = "Unavailable",
                    isSecure = null,
                    permissionDenied = false,
                    details = "Observed edge: shell -> su:process transition. This is only evaluated for confirmed user builds because stock user builds should not expose an AOSP su transition path. The access oracle could not produce a verdict for this edge. | Reason: Dirty policy oracle self-test failed.",
                ),
            ),
        )

        assertTrue(
            model.methodRows.any {
                it.label == "Dirty sepolicy rule: system_server execmem" &&
                    it.value == "Allowed" &&
                    it.status == DetectorStatus.danger()
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == "Dirty sepolicy rule: untrusted_app -> ksu_file read" &&
                    it.value == "Denied" &&
                    it.status == DetectorStatus.allClear()
            },
        )
        assertTrue(
            model.methodRows.any {
                it.label == "Dirty sepolicy rule: shell -> su transition" &&
                    it.value == "Unavailable" &&
                    it.status == DetectorStatus.info(com.eltavine.duckdetector.core.ui.model.InfoKind.SUPPORT)
            },
        )
        assertTrue(
            model.methodRows.any {
                val detail = it.detail
                it.label == "Dirty sepolicy rule: system_server execmem" &&
                    detail != null &&
                    detail.contains("Observed edge:") &&
                    detail.contains("reported this edge as allowed")
            },
        )
    }

    @Test
    fun `trusted dirty sepolicy hit raises overall selinux warning`() {
        val model = mapper.map(
            baseReport(
                SelinuxCheckResult(
                    method = "Dirty sepolicy rule: system_server execmem",
                    status = "Allowed",
                    isSecure = false,
                    permissionDenied = false,
                    details = "Observed edge: system_server -> system_server:process execmem. This should stay denied on stock policy because executable system_server memory is supporting dirty-policy evidence. The access oracle reported this edge as allowed.",
                ),
            ),
        )

        assertEquals(DetectorStatus.warning(), model.status)
        assertEquals("Enforcing with dirty sepolicy rule", model.verdict)
        assertTrue(model.summary.contains("DirtySepolicy-style access query reported system_server execmem as allowed"))
        assertTrue(model.impactItems.any { it.text.contains("trusted DirtySepolicy-style access rule was allowed") })
    }

    private fun baseReport(vararg methods: SelinuxCheckResult): SelinuxReport {
        return SelinuxReport(
            stage = SelinuxStage.READY,
            mode = SelinuxMode.ENFORCING,
            resolvedStatusLabel = "Enforcing",
            filesystemMounted = true,
            paradoxDetected = false,
            methods = methods.toList(),
            processContext = "u:r:untrusted_app:s0:c1,c2",
            contextType = "untrusted_app",
            policyAnalysis = null,
            auditIntegrity = null,
            androidVersion = "16",
            apiLevel = 36,
        )
    }
}
