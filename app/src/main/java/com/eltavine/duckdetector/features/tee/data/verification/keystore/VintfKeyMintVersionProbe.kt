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
import java.io.File
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.xml.sax.InputSource

class VintfKeyMintVersionProbe(
    private val manifestDirs: List<String> = VINTF_MANIFEST_DIRS,
    private val manifestFiles: List<String> = VINTF_MANIFEST_FILES,
) {

    fun inspect(snapshot: AttestationSnapshot): VintfKeyMintVersionResult {
        val manifest = readManifests()
        val actualKeymasterVersion = snapshot.keymasterVersion
        val actualAttestationVersion = snapshot.attestationVersion
        // Tier and version-family mismatches are treated as hard mismatches before any declaration match,
        // because mixing TEE vs StrongBox or Keymaster vs KeyMint would let us compare the wrong backend.
        // 在做 declaration 匹配之前，先把 tier 和版本家族不一致当成硬 mismatch；否则可能把 TEE 和
        // StrongBox、或者 Keymaster 和 KeyMint 交叉比较，最后得出一个“看起来匹配、其实对象错了”的结论。
        val versionFamilyMismatch = actualKeymasterVersion != null && actualAttestationVersion != null &&
            (actualKeymasterVersion >= 100) != (actualAttestationVersion >= 100)
        val tierMismatch = snapshot.attestationTier != null && snapshot.keymasterTier != null &&
            snapshot.attestationTier != snapshot.keymasterTier
        val keyMintAttestation = maxOf(actualKeymasterVersion ?: 0, actualAttestationVersion ?: 0) >= 100
        val selectedTier = snapshot.keymasterTier ?: snapshot.attestationTier ?: snapshot.tier
        val expectedInstance = if (selectedTier == TeeTier.STRONGBOX) {
            STRONGBOX_INSTANCE
        } else {
            DEFAULT_INSTANCE
        }
        val comparedDeclarations = if (tierMismatch) {
            emptyList()
        } else {
            manifest.declarations.filter { declaration ->
                if (keyMintAttestation) {
                    declaration.family == VintfKeyMintVersionFamily.KEYMINT_AIDL &&
                        declaration.instance == expectedInstance
                } else {
                    declaration.family == VintfKeyMintVersionFamily.KEYMASTER_HIDL &&
                        declaration.instance == expectedInstance
                }
            }
        }
        val hasActualVersion = actualKeymasterVersion != null || actualAttestationVersion != null
        val mismatch = comparedDeclarations.isNotEmpty() &&
            hasActualVersion &&
            comparedDeclarations.none { it.matches(actualKeymasterVersion, actualAttestationVersion) }
        val anomalyKind = when {
            tierMismatch || versionFamilyMismatch || mismatch -> VintfKeyMintVersionAnomalyKind.MISMATCH
            manifest.unreadablePaths.isNotEmpty() -> VintfKeyMintVersionAnomalyKind.UNREADABLE
            comparedDeclarations.isEmpty() -> VintfKeyMintVersionAnomalyKind.NO_DECLARATION
            !hasActualVersion -> VintfKeyMintVersionAnomalyKind.NO_ATTESTED_VERSION
            else -> VintfKeyMintVersionAnomalyKind.NONE
        }

        return VintfKeyMintVersionResult(
            readable = manifest.unreadablePaths.isEmpty(),
            anomalyKind = anomalyKind,
            declarations = manifest.declarations,
            comparedDeclarations = comparedDeclarations,
            unreadablePaths = manifest.unreadablePaths,
            attestationVersion = actualAttestationVersion,
            keymasterVersion = actualKeymasterVersion,
            detail = when {
                tierMismatch -> "Attestation and keymaster security levels disagree: " +
                    "attestation=${snapshot.attestationTier}, keymaster=${snapshot.keymasterTier}."
                versionFamilyMismatch -> "Attestation and keymaster versions disagree on HAL family: " +
                    "attestation=$actualAttestationVersion, keymaster=$actualKeymasterVersion."
                else -> detailFor(
                    anomalyKind = anomalyKind,
                    comparedDeclarations = comparedDeclarations,
                    unreadablePaths = manifest.unreadablePaths,
                    attestationVersion = actualAttestationVersion,
                    keymasterVersion = actualKeymasterVersion,
                )
            },
        )
    }

    private fun readManifests(): ManifestReadResult {
        val files = linkedMapOf<String, File>()
        val unreadablePaths = mutableListOf<String>()
        manifestDirs.forEach { path ->
            val dir = File(path)
            if (dir.exists()) {
                val listed = runCatching {
                    dir.listFiles { file -> file.isFile && file.name.endsWith(".xml", ignoreCase = true) }
                }.getOrElse { throwable ->
                    unreadablePaths += "$path: ${describe(throwable)}"
                    null
                }
                if (listed == null) {
                    unreadablePaths += path
                } else {
                    listed.forEach { file -> files[file.absolutePath] = file }
                }
            }
        }
        manifestFiles.forEach { path ->
            val file = File(path)
            if (file.exists()) {
                files[file.absolutePath] = file
            }
        }

        val declarations = mutableListOf<VintfKeyMintVersionDeclaration>()
        files.values.forEach { file ->
            val xml = runCatching { file.readText() }.getOrElse { throwable ->
                unreadablePaths += "${file.absolutePath}: ${describe(throwable)}"
                null
            } ?: return@forEach
            declarations += runCatching { parseManifest(file.absolutePath, xml) }.getOrElse { throwable ->
                unreadablePaths += "${file.absolutePath}: ${describe(throwable)}"
                emptyList()
            }
        }
        return ManifestReadResult(
            declarations = declarations.distinct(),
            unreadablePaths = unreadablePaths.distinct(),
        )
    }

    private fun parseManifest(sourcePath: String, xml: String): List<VintfKeyMintVersionDeclaration> {
        val document = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(InputSource(StringReader(xml)))
        val declarations = mutableListOf<VintfKeyMintVersionDeclaration>()

        directChildElements(document.documentElement, "hal").forEach { halElement ->
            val hal = HalBuilder(
                sourcePath = sourcePath,
                format = halElement.getAttribute("format").orEmpty(),
                halName = directChildTexts(halElement, "name").firstOrNull().orEmpty(),
            )
            hal.versions += directChildTexts(halElement, "version")
            hal.fqnames += directChildTexts(halElement, "fqname")
            directChildElements(halElement, "interface").forEach { interfaceElement ->
                val name = directChildTexts(interfaceElement, "name").firstOrNull()
                if (name != null) {
                    hal.interfaces.getOrPut(name) { mutableSetOf() }
                        .addAll(directChildTexts(interfaceElement, "instance"))
                }
            }
            declarations += hal.toDeclarations()
        }

        return declarations
    }

    private fun directChildElements(parent: Element, tagName: String): List<Element> {
        return buildList {
            val children = parent.childNodes
            for (index in 0 until children.length) {
                val child = children.item(index)
                if (child is Element && child.tagName == tagName) {
                    add(child)
                }
            }
        }
    }

    private fun directChildTexts(parent: Element, tagName: String): List<String> {
        return directChildElements(parent, tagName)
            .map { it.textContent.trim() }
            .filter { it.isNotEmpty() }
    }

    private fun detailFor(
        anomalyKind: VintfKeyMintVersionAnomalyKind,
        comparedDeclarations: List<VintfKeyMintVersionDeclaration>,
        unreadablePaths: List<String>,
        attestationVersion: Int?,
        keymasterVersion: Int?,
    ): String = buildString {
        append("kind=")
        append(anomalyKind.name)
        append(" keymasterVersion=")
        append(keymasterVersion ?: "null")
        append(" attestationVersion=")
        append(attestationVersion ?: "null")
        if (comparedDeclarations.isNotEmpty()) {
            append(" vintf=")
            append(comparedDeclarations.joinToString { it.summary })
        }
        if (unreadablePaths.isNotEmpty()) {
            append(" unreadable=")
            append(unreadablePaths.joinToString())
        }
    }

    private fun describe(throwable: Throwable): String {
        return "${throwable.javaClass.simpleName}: ${throwable.message ?: "no message"}"
    }

    private data class ManifestReadResult(
        val declarations: List<VintfKeyMintVersionDeclaration>,
        val unreadablePaths: List<String>,
    )

    private data class HalBuilder(
        val sourcePath: String,
        val format: String,
        var halName: String = "",
        val versions: MutableList<String> = mutableListOf(),
        val interfaces: MutableMap<String, MutableSet<String>> = mutableMapOf(),
        val fqnames: MutableList<String> = mutableListOf(),
    ) {
        fun toDeclarations(): List<VintfKeyMintVersionDeclaration> {
            return when (halName) {
                KEYMINT_HAL_NAME -> keyMintDeclarations()
                KEYMASTER_HAL_NAME -> keymasterDeclarations()
                else -> emptyList()
            }
        }

        private fun keyMintDeclarations(): List<VintfKeyMintVersionDeclaration> {
            val instances = interfaceInstances(KEYMINT_INTERFACE_NAME)
                .filter { it == DEFAULT_INSTANCE || it == STRONGBOX_INSTANCE }
            if (instances.isEmpty()) {
                return emptyList()
            }
            // Versionless AIDL HAL declarations mean version 1 in VINTF practice; treating them as missing
            // would create a false NO_DECLARATION / false legacy skip on valid KeyMint 1 devices.
            // VINTF 里未显式写 version 的 AIDL HAL 在实践中等价于 version 1；如果当作缺失处理，会把
            // 合法的 KeyMint 1 设备误报成没有声明，甚至误走 legacy skip。
            val aidlVersions = versions.ifEmpty { listOf(DEFAULT_AIDL_VERSION) }
            return instances.flatMap { instance ->
                aidlVersions.mapNotNull { version ->
                    version.toIntOrNull()?.takeIf { it > 0 }?.let { aidlVersion ->
                        VintfKeyMintVersionDeclaration(
                            family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
                            sourcePath = sourcePath,
                            format = format,
                            halName = halName,
                            interfaceName = KEYMINT_INTERFACE_NAME,
                            instance = instance,
                            vintfVersion = version,
                            expectedKeymasterVersion = aidlVersion * 100,
                            expectedAttestationVersion = aidlVersion * 100,
                        )
                    }
                }
            }
        }

        private fun interfaceInstances(interfaceName: String): Set<String> {
            val fqnameInstances = fqnames.mapNotNull { fqname ->
                val name = fqname.substringAfter("::", fqname).substringBefore("/")
                val instance = fqname.substringAfter("/", "")
                instance.takeIf { name == interfaceName && it.isNotEmpty() }
            }
            return (interfaces[interfaceName].orEmpty() + fqnameInstances).toSet()
        }

        private fun keymasterDeclarations(): List<VintfKeyMintVersionDeclaration> {
            // For HIDL we must preserve the exact version-instance association from fqname.
            // A naive cross-product would wrongly synthesize nonexistent pairs such as
            // default@4.1 when the manifest only declares strongbox@4.1.
            // HIDL 这里必须保留 fqname 中“版本-实例”的原始绑定关系；如果做笛卡尔积，就会伪造出
            // manifest 根本没声明的 default@4.1 之类组合。
            val interfaceDeclaredInstances = interfaces[KEYMASTER_INTERFACE_NAME].orEmpty()
                .filter { it == DEFAULT_INSTANCE || it == STRONGBOX_INSTANCE }
            val interfaceDeclarations = interfaceDeclaredInstances.flatMap { instance ->
                versions.flatMap(::expandHidlVersions).distinct().mapNotNull { version ->
                    val expected = expectedLegacyVersions(version) ?: return@mapNotNull null
                    legacyDeclaration(instance, version, expected)
                }
            }
            val fqnameDeclarations = fqnames.mapNotNull { fqname ->
                val parsed = parseHidlFqname(fqname) ?: return@mapNotNull null
                if (
                    parsed.interfaceName != KEYMASTER_INTERFACE_NAME ||
                    (parsed.instance != DEFAULT_INSTANCE && parsed.instance != STRONGBOX_INSTANCE)
                ) {
                    return@mapNotNull null
                }
                val expected = expectedLegacyVersions(parsed.version) ?: return@mapNotNull null
                legacyDeclaration(parsed.instance, parsed.version, expected)
            }
            return (interfaceDeclarations + fqnameDeclarations).distinct()
        }

        private fun legacyDeclaration(
            instance: String,
            version: String,
            expected: Pair<Int, Int>,
        ): VintfKeyMintVersionDeclaration {
            return VintfKeyMintVersionDeclaration(
                family = VintfKeyMintVersionFamily.KEYMASTER_HIDL,
                sourcePath = sourcePath,
                format = format,
                halName = halName,
                interfaceName = KEYMASTER_INTERFACE_NAME,
                instance = instance,
                vintfVersion = version,
                expectedKeymasterVersion = expected.first,
                expectedAttestationVersion = expected.second,
            )
        }

        private fun parseHidlFqname(fqname: String): ParsedHidlFqname? {
            val match = HIDL_FQNAME_REGEX.matchEntire(fqname) ?: return null
            return ParsedHidlFqname(
                version = match.groupValues[1],
                interfaceName = match.groupValues[2],
                instance = match.groupValues[3],
            )
        }
    }

    companion object {
        private val VINTF_MANIFEST_DIRS = listOf(
            "/system/etc/vintf/manifest",
            "/system_ext/etc/vintf/manifest",
            "/product/etc/vintf/manifest",
            "/vendor/etc/vintf/manifest",
            "/odm/etc/vintf/manifest",
        )
        private val VINTF_MANIFEST_FILES = listOf(
            "/system/etc/vintf/manifest.xml",
            "/system_ext/etc/vintf/manifest.xml",
            "/product/etc/vintf/manifest.xml",
            "/vendor/etc/vintf/manifest.xml",
            "/odm/etc/vintf/manifest.xml",
        )
        private const val KEYMINT_HAL_NAME = "android.hardware.security.keymint"
        private const val KEYMASTER_HAL_NAME = "android.hardware.keymaster"
        private const val KEYMINT_INTERFACE_NAME = "IKeyMintDevice"
        private const val KEYMASTER_INTERFACE_NAME = "IKeymasterDevice"
        private const val DEFAULT_INSTANCE = "default"
        private const val STRONGBOX_INSTANCE = "strongbox"
        private const val DEFAULT_AIDL_VERSION = "1"
        private val HIDL_FQNAME_REGEX = Regex("^@([0-9]+(?:\\.[0-9]+)?)::([^/]+)/(.+)$")

        private fun expectedLegacyVersions(version: String): Pair<Int, Int>? {
            return when (version) {
                "3.0" -> 3 to 2
                "4.0" -> 4 to 3
                "4.1" -> 41 to 4
                else -> null
            }
        }

        private fun expandHidlVersions(version: String): List<String> {
            val range = HIDL_VERSION_RANGE_REGEX.matchEntire(version) ?: return listOf(version)
            val major = range.groupValues[1]
            val firstMinor = range.groupValues[2].toInt()
            val lastMinor = range.groupValues[3].toInt()
            return (firstMinor..lastMinor).map { minor -> "$major.$minor" }
        }

        private val HIDL_VERSION_RANGE_REGEX = Regex("^([0-9]+)\\.([0-9]+)-([0-9]+)$")
    }

    private data class ParsedHidlFqname(
        val version: String,
        val interfaceName: String,
        val instance: String,
    )
}

enum class VintfKeyMintVersionFamily {
    KEYMINT_AIDL,
    KEYMASTER_HIDL,
}

enum class VintfKeyMintVersionAnomalyKind {
    NONE,
    UNREADABLE,
    NO_DECLARATION,
    NO_ATTESTED_VERSION,
    MISMATCH,
}

data class VintfKeyMintVersionDeclaration(
    val family: VintfKeyMintVersionFamily,
    val sourcePath: String,
    val format: String,
    val halName: String,
    val interfaceName: String,
    val instance: String,
    val vintfVersion: String,
    val expectedKeymasterVersion: Int,
    val expectedAttestationVersion: Int,
) {
    val summary: String
        get() = "$halName/$interfaceName/$instance@$vintfVersion -> " +
            "keymaster=$expectedKeymasterVersion,attestation=$expectedAttestationVersion"

    fun matches(keymasterVersion: Int?, attestationVersion: Int?): Boolean {
        return (keymasterVersion == null || keymasterVersion == expectedKeymasterVersion) &&
            (attestationVersion == null || attestationVersion == expectedAttestationVersion)
    }
}

data class VintfKeyMintVersionResult(
    val readable: Boolean,
    val anomalyKind: VintfKeyMintVersionAnomalyKind,
    val declarations: List<VintfKeyMintVersionDeclaration> = emptyList(),
    val comparedDeclarations: List<VintfKeyMintVersionDeclaration> = emptyList(),
    val unreadablePaths: List<String> = emptyList(),
    val attestationVersion: Int? = null,
    val keymasterVersion: Int? = null,
    val detail: String,
) {
    val diagnosticCopyText: String
        get() = buildString {
            append("kind=")
            append(anomalyKind.name)
            append('\n')
            append("readable=")
            append(readable)
            append('\n')
            append("attestationVersion=")
            append(attestationVersion ?: "null")
            append('\n')
            append("keymasterVersion=")
            append(keymasterVersion ?: "null")
            append('\n')
            append("comparedDeclarations=")
            append(comparedDeclarations.joinToString { it.summary }.ifBlank { "none" })
            append('\n')
            append("allDeclarations=")
            append(declarations.joinToString { it.summary }.ifBlank { "none" })
            append('\n')
            append("unreadablePaths=")
            append(unreadablePaths.joinToString().ifBlank { "none" })
            append('\n')
            append(detail)
        }
}
