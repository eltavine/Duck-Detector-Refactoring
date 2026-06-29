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
        val keyMintAttestation = (actualKeymasterVersion ?: actualAttestationVersion ?: 0) >= 100
        val comparedDeclarations = manifest.declarations.filter { declaration ->
            if (keyMintAttestation) {
                declaration.family == VintfKeyMintVersionFamily.KEYMINT_AIDL
            } else {
                declaration.family == VintfKeyMintVersionFamily.KEYMASTER_HIDL
            }
        }
        val hasActualVersion = actualKeymasterVersion != null || actualAttestationVersion != null
        val mismatch = comparedDeclarations.isNotEmpty() &&
            hasActualVersion &&
            comparedDeclarations.none { it.matches(actualKeymasterVersion, actualAttestationVersion) }
        val anomalyKind = when {
            mismatch -> VintfKeyMintVersionAnomalyKind.MISMATCH
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
            detail = detailFor(
                anomalyKind = anomalyKind,
                comparedDeclarations = comparedDeclarations,
                unreadablePaths = manifest.unreadablePaths,
                attestationVersion = actualAttestationVersion,
                keymasterVersion = actualKeymasterVersion,
            ),
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
            if (!hasInstance(KEYMINT_INTERFACE_NAME, DEFAULT_INSTANCE)) {
                return emptyList()
            }
            return versions.mapNotNull { version ->
                version.toIntOrNull()?.takeIf { it > 0 }?.let { aidlVersion ->
                    VintfKeyMintVersionDeclaration(
                        family = VintfKeyMintVersionFamily.KEYMINT_AIDL,
                        sourcePath = sourcePath,
                        format = format,
                        halName = halName,
                        interfaceName = KEYMINT_INTERFACE_NAME,
                        instance = DEFAULT_INSTANCE,
                        vintfVersion = version,
                        expectedKeymasterVersion = aidlVersion * 100,
                        expectedAttestationVersion = aidlVersion * 100,
                    )
                }
            }
        }

        private fun keymasterDeclarations(): List<VintfKeyMintVersionDeclaration> {
            if (!hasInstance(KEYMASTER_INTERFACE_NAME, DEFAULT_INSTANCE)) {
                return emptyList()
            }
            return (versions.flatMap(::expandHidlVersions) + fqnames.mapNotNull(::versionFromFqname))
                .distinct()
                .mapNotNull { version ->
                    val expected = expectedLegacyVersions(version) ?: return@mapNotNull null
                    VintfKeyMintVersionDeclaration(
                        family = VintfKeyMintVersionFamily.KEYMASTER_HIDL,
                        sourcePath = sourcePath,
                        format = format,
                        halName = halName,
                        interfaceName = KEYMASTER_INTERFACE_NAME,
                        instance = DEFAULT_INSTANCE,
                        vintfVersion = version,
                        expectedKeymasterVersion = expected.first,
                        expectedAttestationVersion = expected.second,
                    )
                }
        }

        private fun hasInstance(interfaceName: String, instance: String): Boolean {
            return fqnames.any { fqname ->
                fqname.substringAfter("::", fqname).substringBefore("/") == interfaceName &&
                    fqname.substringAfter("/", "") == instance
            } || (interfaces[interfaceName]?.contains(instance) == true)
        }

        private fun versionFromFqname(fqname: String): String? {
            return FQNAME_VERSION_REGEX.find(fqname)?.groupValues?.getOrNull(1)
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
        private val FQNAME_VERSION_REGEX = Regex("^@([0-9]+(?:\\.[0-9]+)?)::")

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
