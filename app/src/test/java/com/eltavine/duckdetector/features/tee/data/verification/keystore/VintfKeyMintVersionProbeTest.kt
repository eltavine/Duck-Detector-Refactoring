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
    fun `old vendor aidl matching applies fallback rule to both attestation fields`() {
        val declaration = keyMintDeclaration(aidlVersion = 5)

        assertTrue(declaration.matches(400, 300, 202504))
        assertTrue(!declaration.matches(550, 400, 202504))
        assertTrue(!declaration.matches(400, 350, 202504))
    }

    @Test
    fun `new vendor aidl matching requires both attestation fields to equal declaration`() {
        val declaration = keyMintDeclaration(aidlVersion = 5)

        assertTrue(declaration.matches(500, 500, 202604))
        assertTrue(!declaration.matches(400, 500, 202604))
        assertTrue(!declaration.matches(500, 400, 202604))
    }

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
                vendorApiLevelReader = vendorApiLevelReader(202404),
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
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 300, keymasterVersion = 41))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
            assertTrue(result.detail.contains("HAL family"))
        }
    }

    @Test
    fun `keymint runtime version disagreement is a mismatch`() {
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
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 100, keymasterVersion = 300))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
            assertTrue(result.detail.contains("runtime identity"))
        }
    }

    @Test
    fun `older keymint runtime is compatible with newer aidl declaration on old vendor api`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>5</version>
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
                vendorApiLevelReader = vendorApiLevelReader(202504),
            ).inspect(snapshot(attestationVersion = 400, keymasterVersion = 400))

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertTrue(result.comparedDeclarations.single().matches(400, 400, 202504))
        }
    }

    @Test
    fun `older keymint runtime mismatches newer aidl declaration on new vendor api`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>5</version>
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
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 400, keymasterVersion = 400))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
        }
    }

    @Test
    fun `unknown vendor api cannot return clean aidl comparison`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>5</version>
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
                vendorApiLevelReader = VendorApiLevelReader {
                    VendorApiLevelResult(null, "test vendor API unavailable")
                },
            ).inspect(snapshot(attestationVersion = 500, keymasterVersion = 500))

            assertEquals(VintfKeyMintVersionAnomalyKind.UNREADABLE, result.anomalyKind)
            assertTrue(!result.readable)
            assertTrue(result.detail.contains("vendor API level could not be determined"))
        }
    }

    @Test
    fun `keymint runtime above aidl declaration remains mismatch`() {
        withManifest(
            """
            <manifest version="1.0" type="device">
                <hal format="aidl">
                    <name>android.hardware.security.keymint</name>
                    <version>5</version>
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
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 600, keymasterVersion = 600))

            assertEquals(VintfKeyMintVersionAnomalyKind.MISMATCH, result.anomalyKind)
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
                vendorApiLevelReader = vendorApiLevelReader(202604),
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

    @Test
    fun `malformed unrelated vintf fragments do not poison keymint result`() {
        withManifestDirectory(
            mapOf(
                "android.hardware.security.keymint.xml" to """
                    <manifest version="1.0" type="device">
                        <hal format="aidl">
                            <name>android.hardware.security.keymint</name>
                            <version>2</version>
                            <interface>
                                <name>IKeyMintDevice</name>
                                <instance>default</instance>
                            </interface>
                        </hal>
                    </manifest>
                """.trimIndent(),
                "atcmdfwd-saidl.xml" to "/* Copyright */\nnot xml",
                "vendor.qti.qesdsys.service.xml" to "/** Copyright */\nstill not xml",
            ),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = listOf(path),
                manifestFiles = emptyList(),
                vendorApiLevelReader = vendorApiLevelReader(202604),
            ).inspect(snapshot(attestationVersion = 200, keymasterVersion = 200))

            assertEquals(VintfKeyMintVersionAnomalyKind.NONE, result.anomalyKind)
            assertTrue(result.readable)
            assertTrue(result.unreadablePaths.isEmpty())
        }
    }

    @Test
    fun `malformed keymint fragment remains unreadable`() {
        withManifestDirectory(
            mapOf(
                "android.hardware.security.keymint.xml" to """
                    /* Copyright */
                    <manifest version="1.0" type="device">
                        <hal format="aidl">
                            <name>android.hardware.security.keymint</name>
                        </hal>
                    </manifest>
                """.trimIndent(),
            ),
        ) { path ->
            val result = VintfKeyMintVersionProbe(
                manifestDirs = listOf(path),
                manifestFiles = emptyList(),
            ).inspect(snapshot(attestationVersion = 200, keymasterVersion = 200))

            assertEquals(VintfKeyMintVersionAnomalyKind.UNREADABLE, result.anomalyKind)
            assertTrue(!result.readable)
            assertTrue(result.unreadablePaths.single().contains("keymint"))
        }
    }

    @Test
    fun `vendor api resolver uses direct vendor property first`() {
        val properties = mapOf(
            "ro.vendor.api_level" to "202604",
            "ro.board.api_level" to "202504",
            "ro.product.first_api_level" to "35",
        )

        val result = resolveVendorApiLevel(properties::get)

        assertEquals(202604, result.level)
        assertTrue(result.detail.contains("ro.vendor.api_level"))
    }

    @Test
    fun `vendor api resolver mirrors vts board and product minimum`() {
        val properties = mapOf(
            "ro.vendor.api_level" to "-1",
            "ro.board.api_level" to "202604",
            "ro.product.first_api_level" to "202504",
        )

        val result = resolveVendorApiLevel(properties::get)

        assertEquals(202504, result.level)
        assertTrue(result.detail.contains("min(productApi=202504, boardApi=202604)"))
    }

    @Test
    fun `vendor api resolver uses product when board properties are absent`() {
        val properties = mapOf(
            "ro.product.first_api_level" to "202504",
        )

        val result = resolveVendorApiLevel(properties::get)

        assertEquals(202504, result.level)
        assertTrue(result.detail.contains("boardApi=absent"))
    }

    @Test
    fun `vendor api resolver falls back to build sdk and reports unknown when absent`() {
        assertEquals(
            37,
            resolveVendorApiLevel(mapOf("ro.build.version.sdk" to "37")::get).level,
        )

        val unknown = resolveVendorApiLevel(emptyMap<String, String>()::get)
        assertEquals(null, unknown.level)
        assertTrue(unknown.detail.contains("Missing"))
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

    private fun withManifestDirectory(files: Map<String, String>, block: (String) -> Unit) {
        val dir = Files.createTempDirectory("duck_vintf_dir").toFile()
        try {
            files.forEach { (name, content) -> dir.resolve(name).writeText(content) }
            block(dir.absolutePath)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun vendorApiLevelReader(level: Int): VendorApiLevelReader = VendorApiLevelReader {
        VendorApiLevelResult(level, "test vendor API level=$level")
    }

    private fun keyMintDeclaration(aidlVersion: Int): VintfKeyMintVersionDeclaration {
        return VintfKeyMintVersionDeclaration(
            family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
            sourcePath = "/test/manifest.xml",
            format = "aidl",
            halName = "android.hardware.security.keymint",
            interfaceName = "IKeyMintDevice",
            instance = "default",
            vintfVersion = aidlVersion.toString(),
            expectedKeymasterVersion = aidlVersion * 100,
            expectedAttestationVersion = aidlVersion * 100,
        )
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
