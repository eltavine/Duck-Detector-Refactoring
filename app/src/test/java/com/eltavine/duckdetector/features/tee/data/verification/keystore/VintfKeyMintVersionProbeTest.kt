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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import com.eltavine.duckdetector.features.tee.data.attestation.AttestationSnapshot
import com.eltavine.duckdetector.features.tee.domain.TeeTier
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VintfKeyMintVersionProbeTest {

    @Test
    fun `hidl version range expands for keymaster 4_1`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="hidl">
                    <name>android.hardware.keymaster</name>
                    <transport>hwbinder</transport>
                    <version>4.0-1</version>
                    <interface>
                        <name>IKeymasterDevice</name>
                        <instance>default</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(snapshot(attestationVersion = 4, keymasterVersion = 41))

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertTrue(result.comparedDeclarations.any { it.vintfVersion == "4.1" })
        }
    }

    @Test
    fun `interface instances are not cross matched`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>4</version>
                    <interface>
                        <name>IKeyMintDevice</name>
                        <instance>strongbox</instance>
                    </interface>
                    <interface>
                        <name>IRemotelyProvisionedComponent</name>
                        <instance>default</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(snapshot(attestationVersion = 400, keymasterVersion = 400))

            assertEquals(VintfKeyMintVersionAnomalyKind.NO_DECLARATION, result.anomalyKind)
        }
    }

    private fun withManifest(xml: String, block: (String) -> Unit) {
        val dir = Files.createTempDirectory("duck_vintf").toFile()
        try {
            val manifest = dir.resolve("manifest.xml")
            manifest.writeText(xml)
            block(manifest.absolutePath)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun snapshot(attestationVersion: Int?, keymasterVersion: Int?): AttestationSnapshot {
        return AttestationSnapshot(
            tier = TeeTier.TEE,
            attestationVersion = attestationVersion,
            keymasterVersion = keymasterVersion,
            attestationTier = TeeTier.TEE,
            keymasterTier = TeeTier.TEE,
            challengeVerified = true,
            challengeSummary = "ok",
            rootOfTrust = null,
            osVersion = null,
            osPatchLevel = null,
            vendorPatchLevel = null,
            bootPatchLevel = null,
            rawCertificates = emptyList(),
            displayCertificates = emptyList(),
        )
    }
}
