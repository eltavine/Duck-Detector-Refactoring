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
            assertTrue(result.declarations.any { it.instance == "strongbox" })
        }
    }

    @Test
    fun `strongbox attestation compares strongbox aidl declaration`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>2</version>
                    <interface>
                        <name>IKeyMintDevice</name>
                        <instance>strongbox</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(
                snapshot(attestationVersion = 200, keymasterVersion = 200).copy(
                    tier = TeeTier.STRONGBOX,
                    attestationTier = TeeTier.STRONGBOX,
                    keymasterTier = TeeTier.STRONGBOX,
                ),
            )

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertEquals("strongbox", result.comparedDeclarations.single().instance)
        }
    }

    @Test
    fun `strongbox attestation compares strongbox keymaster declaration`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="hidl">
                    <name>android.hardware.keymaster</name>
                    <version>4.1</version>
                    <interface>
                        <name>IKeymasterDevice</name>
                        <instance>strongbox</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(
                snapshot(attestationVersion = 4, keymasterVersion = 41).copy(
                    tier = TeeTier.STRONGBOX,
                    attestationTier = TeeTier.STRONGBOX,
                    keymasterTier = TeeTier.STRONGBOX,
                ),
            )

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertEquals("strongbox", result.comparedDeclarations.single().instance)
        }
    }

    @Test
    fun `security level disagreement is a mismatch`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>3</version>
                    <interface>
                        <name>IKeyMintDevice</name>
                        <instance>default</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(
                snapshot(attestationVersion = 300, keymasterVersion = 300).copy(
                    attestationTier = TeeTier.TEE,
                    keymasterTier = TeeTier.STRONGBOX,
                ),
            )

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
            assertTrue(result.detail.contains("security levels disagree"))
        }
    }

    @Test
    fun `version family disagreement is a mismatch`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>3</version>
                    <interface>
                        <name>IKeyMintDevice</name>
                        <instance>default</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(snapshot(attestationVersion = 300, keymasterVersion = 41))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
            assertTrue(result.detail.contains("HAL family"))
        }
    }

    @Test
    fun `versionless aidl declaration defaults to keymint1`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <interface>
                        <name>IKeyMintDevice</name>
                        <instance>default</instance>
                    </interface>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(snapshot(attestationVersion = 100, keymasterVersion = 100))

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertEquals("1", result.comparedDeclarations.single().vintfVersion)
        }
    }

    @Test
    fun `hidl fqname preserves version instance association`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="hidl">
                    <name>android.hardware.keymaster</name>
                    <fqname>@4.0::IKeymasterDevice/default</fqname>
                    <fqname>@4.1::IKeymasterDevice/strongbox</fqname>
                </hal>
            </manifest>
            """.trimIndent(),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = emptyList(),
                manifestFiles = listOf(path),
            ).inspect(snapshot(attestationVersion = 4, keymasterVersion = 41))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
            assertEquals(listOf("4.0"), result.comparedDeclarations.map { it.vintfVersion })
            assertTrue(result.declarations.none {
                it.instance == "default" && it.vintfVersion == "4.1"
            })
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
