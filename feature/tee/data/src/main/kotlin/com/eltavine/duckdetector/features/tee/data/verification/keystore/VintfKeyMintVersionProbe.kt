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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.core.platform.HiddenSystemProperties
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import java.io.File
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.xml.sax.InputSource

class VintfKeyMintVersionProbe(
    private val manifestDirs: List<String> = VINTF_MANIFEST_DIRS,
    private val manifestFiles: List<String> = VINTF_MANIFEST_FILES,
    private val vendorApiLevelReader: VendorApiLevelReader = ReflectionVendorApiLevelReader(),
) {

    fun inspect(snapshot: AttestationSnapshot): VintfKeyMintVersionResult {
        val skuManifestPaths = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ensureHiddenApiAccess()
            currentSkuManifestPaths(
                vendorSku = HiddenSystemProperties.read("ro.boot.product.vendor.sku").getOrNull(),
                odmSku = Build.ODM_SKU.takeUnless { it == Build.UNKNOWN },
            )
        } else {
            emptyList()
        }
        return inspect(snapshot, skuManifestPaths)
    }

    internal fun inspect(snapshot: AttestationSnapshot, skuManifestPaths: List<String>): VintfKeyMintVersionResult {
        val manifest = readManifests(skuManifestPaths)
        val actualKeymasterVersion = snapshot.keymasterVersion
        val actualAttestationVersion = snapshot.attestationVersion
        // Tier and version-family mismatches are treated as hard mismatches before any declaration match,
        // because mixing TEE vs StrongBox or Keymaster vs KeyMint would let us compare the wrong backend.
        // 在做 declaration 匹配之前，先把 tier 和版本家族不一致当成硬 mismatch；否则可能把 TEE 和
        // StrongBox、或者 Keymaster 和 KeyMint 交叉比较，最后得出一个“看起来匹配、其实对象错了”的结论。
        val versionFamilyMismatch = actualKeymasterVersion != null && actualAttestationVersion != null &&
            (actualKeymasterVersion >= 100) != (actualAttestationVersion >= 100)
        val keyMintRuntimeIdentityMismatch = actualKeymasterVersion != null &&
            actualAttestationVersion != null &&
            actualKeymasterVersion >= 100 &&
            actualAttestationVersion >= 100 &&
            actualKeymasterVersion != actualAttestationVersion
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
        val requiresVendorApiLevel = hasActualVersion && comparedDeclarations.any {
            it.family == VintfKeyMintVersionFamily.KEYMINT_AIDL
        }
        val vendorApiLevel = if (requiresVendorApiLevel) {
            vendorApiLevelReader.read()
        } else {
            VendorApiLevelResult.unused()
        }
        val vendorApiUnavailable = requiresVendorApiLevel && vendorApiLevel.level == null
        val mismatch = !vendorApiUnavailable &&
            comparedDeclarations.isNotEmpty() &&
            hasActualVersion &&
            comparedDeclarations.none {
                it.matches(
                    keymasterVersion = actualKeymasterVersion,
                    attestationVersion = actualAttestationVersion,
                    vendorApiLevel = vendorApiLevel.level,
                )
            }
        val anomalyKind = when {
            tierMismatch || versionFamilyMismatch || keyMintRuntimeIdentityMismatch || mismatch ->
                VintfKeyMintVersionAnomalyKind.MISMATCH
            manifest.unreadablePaths.isNotEmpty() || vendorApiUnavailable ->
                VintfKeyMintVersionAnomalyKind.UNREADABLE
            comparedDeclarations.isEmpty() -> VintfKeyMintVersionAnomalyKind.NO_DECLARATION
            !hasActualVersion -> VintfKeyMintVersionAnomalyKind.NO_ATTESTED_VERSION
            else -> VintfKeyMintVersionAnomalyKind.NONE
        }

        return VintfKeyMintVersionResult(
            readable = manifest.unreadablePaths.isEmpty() && !vendorApiUnavailable,
            anomalyKind = anomalyKind,
            declarations = manifest.declarations,
            comparedDeclarations = comparedDeclarations,
            unreadablePaths = manifest.unreadablePaths,
            attestationVersion = actualAttestationVersion,
            keymasterVersion = actualKeymasterVersion,
            vendorApiLevel = vendorApiLevel.level,
            vendorApiDetail = vendorApiLevel.detail,
            detail = when {
                tierMismatch -> "Attestation and keymaster security levels disagree: " +
                    "attestation=${snapshot.attestationTier}, keymaster=${snapshot.keymasterTier}."
                versionFamilyMismatch -> "Attestation and keymaster versions disagree on HAL family: " +
                    "attestation=$actualAttestationVersion, keymaster=$actualKeymasterVersion."
                keyMintRuntimeIdentityMismatch -> "Attestation and keymaster versions disagree on KeyMint " +
                    "runtime identity: attestation=$actualAttestationVersion, keymaster=$actualKeymasterVersion."
                vendorApiUnavailable -> "KeyMint AIDL version comparison was incomplete because the " +
                    "vendor API level could not be determined. ${vendorApiLevel.detail}"
                else -> detailFor(
                    anomalyKind = anomalyKind,
                    comparedDeclarations = comparedDeclarations,
                    unreadablePaths = manifest.unreadablePaths,
                    attestationVersion = actualAttestationVersion,
                    keymasterVersion = actualKeymasterVersion,
                )
            },
            strongBoxManifestPaths = manifest.strongBoxPaths,
        )
    }

    internal fun mergedDeviceManifestDeclaresStrongBox(
        readReport: () -> Array<*>? = {
            // On Android 13, libvintf merges the device manifest directly in this process.
            ensureHiddenApiAccess()
            loadClass("android.os.VintfObject").getMethod("report").invoke(null) as? Array<*>
        },
    ): Boolean? {
        val reports = runCatching(readReport).getOrNull() ?: return null
        return reports.asSequence()
            .filterIsInstance<String>()
            .mapNotNull { xml -> runCatching { parseManifest("merged device manifest", xml) }.getOrNull() }
            .firstOrNull { it.isDeviceManifest }
            ?.declaresStrongBox
    }

    private fun readManifests(skuManifestPaths: List<String>): ManifestReadResult {
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
        val strongBoxPaths = mutableListOf<String>()
        val skuFiles = skuManifestPaths.map(::File).filter { it.isFile }.associateBy { it.absolutePath }
        (files + skuFiles).forEach { (path, file) ->
            // SKU files supplement the StrongBox file evidence without affecting the version comparison.
            val compareVersions = path in files
            val xml = runCatching { file.readText() }.getOrElse { throwable ->
                if (compareVersions && isPotentialKeyMintManifestPath(path, includeAggregateManifest = true)) {
                    unreadablePaths += "$path: ${describe(throwable)}"
                }
                null
            } ?: return@forEach
            // Vendor VINTF directories sometimes contain non-XML fragments for unrelated HALs.
            // Parsing every *.xml file lets those malformed fragments poison an otherwise complete
            // KeyMint result. Only target-bearing fragments participate in this focused probe;
            // malformed KeyMint/Keymaster fragments still fail closed as UNREADABLE.
            // 部分厂商会把其他 HAL 的非 XML 碎片放进 VINTF 目录。若无差别解析全部 *.xml，
            // 无关文件的语法错误会污染已经完整匹配的 KeyMint 结果。这里只解析带目标标识的片段；
            // 真正属于 KeyMint/Keymaster 的损坏片段仍按 UNREADABLE 处理。
            if (!isPotentialKeyMintManifest(path, xml)) {
                return@forEach
            }
            val manifest = runCatching { parseManifest(path, xml) }.getOrElse { throwable ->
                if (compareVersions) unreadablePaths += "$path: ${describe(throwable)}"
                return@forEach
            }
            if (compareVersions) declarations += manifest.declarations
            if (manifest.declaresStrongBox) {
                strongBoxPaths += path
            }
        }
        return ManifestReadResult(
            declarations = declarations.distinct(),
            unreadablePaths = unreadablePaths.distinct(),
            strongBoxPaths = strongBoxPaths,
        )
    }

    private fun parseManifest(sourcePath: String, xml: String): ParsedManifest {
        val root = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(InputSource(StringReader(xml)))
            .documentElement
        val declarations = mutableListOf<VintfKeyMintVersionDeclaration>()

        directChildElements(root, "hal").forEach { halElement ->
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

        return ParsedManifest(
            isDeviceManifest = root.tagName == "manifest" && root.getAttribute("type") == "device",
            declarations = declarations,
        )
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
        return "${PlatformFailureName.of(throwable)}: ${throwable.message ?: "no message"}"
    }

    private fun isPotentialKeyMintManifest(path: String, xml: String): Boolean {
        return isPotentialKeyMintManifestPath(path, includeAggregateManifest = false) ||
            KEYSTORE_HAL_MARKERS.any { marker -> xml.contains(marker, ignoreCase = true) }
    }

    private fun isPotentialKeyMintManifestPath(
        path: String,
        includeAggregateManifest: Boolean,
    ): Boolean {
        val name = File(path).name
        return name.contains("keymint", ignoreCase = true) ||
            name.contains("keymaster", ignoreCase = true) ||
            (includeAggregateManifest && name.equals("manifest.xml", ignoreCase = true))
    }

    private data class ManifestReadResult(
        val declarations: List<VintfKeyMintVersionDeclaration>,
        val unreadablePaths: List<String>,
        val strongBoxPaths: List<String>,
    )

    private data class ParsedManifest(
        val isDeviceManifest: Boolean,
        val declarations: List<VintfKeyMintVersionDeclaration>,
    ) {
        val declaresStrongBox: Boolean
            get() = isDeviceManifest && declarations.any { declaration ->
                declaration.instance == STRONGBOX_INSTANCE && when (declaration.family) {
                    VintfKeyMintVersionFamily.KEYMINT_AIDL -> declaration.format == "aidl"
                    VintfKeyMintVersionFamily.KEYMASTER_HIDL ->
                        (declaration.format == "hidl" || declaration.format.isEmpty()) &&
                            (declaration.vintfVersion == "4.0" || declaration.vintfVersion == "4.1")
                }
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
        internal const val STRICT_KEYMINT_VENDOR_API_THRESHOLD = 202504
        private val KEYSTORE_HAL_MARKERS = listOf(
            KEYMINT_HAL_NAME,
            KEYMASTER_HAL_NAME,
            KEYMINT_INTERFACE_NAME,
            KEYMASTER_INTERFACE_NAME,
        )
    }

}

internal fun currentSkuManifestPaths(vendorSku: String?, odmSku: String?): List<String> = buildList {
    fun safeSku(sku: String?): String? = sku?.takeIf { value ->
        value.isNotBlank() && value.none { it == '/' || it == '\\' || it == '\u0000' }
    }

    safeSku(vendorSku)?.let { add("/vendor/etc/vintf/manifest_$it.xml") }
    safeSku(odmSku)?.let {
        add("/odm/etc/vintf/manifest_$it.xml")
        add("/odm/etc/manifest_$it.xml")
    }
}
