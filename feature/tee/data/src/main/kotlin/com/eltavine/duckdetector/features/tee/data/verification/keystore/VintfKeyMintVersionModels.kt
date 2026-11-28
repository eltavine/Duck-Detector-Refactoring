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

    fun matches(
        keymasterVersion: Int?,
        attestationVersion: Int?,
        vendorApiLevel: Int?,
    ): Boolean {
        return when (family) {
            VintfKeyMintVersionFamily.KEYMINT_AIDL -> {
                vendorApiLevel ?: return false
                if (keymasterVersion == null || attestationVersion == null) {
                    return false
                }
                val versions = listOf(keymasterVersion, attestationVersion)
                if (vendorApiLevel > VintfKeyMintVersionProbe.STRICT_KEYMINT_VENDOR_API_THRESHOLD) {
                    versions.all { version -> version == expectedKeymasterVersion }
                } else {
                    // This mirrors KeyMint VTS check_attestation_version() for both fields.
                    // Both attestationVersion and keymasterVersion may lag the AIDL declaration
                    // only on vendor API <= 36, and must remain 100-based and <= aidlVersion * 100.
                    // 这里对两个字段复刻 VTS 的同一套规则：只有 vendor API <= 36 才允许实现版本
                    // 低于 AIDL 声明，且版本必须是 100 的倍数并且不超过 aidlVersion * 100。
                    //
                    // AOSP references:
                    // hardware/interfaces/security/keymint/aidl/vts/functional/KeyMintAidlTestBase.cpp
                    // https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/vts/functional/KeyMintAidlTestBase.cpp
                    versions.all { version ->
                        version >= 100 && version % 100 == 0 && version <= expectedKeymasterVersion
                    }
                }
            }
            VintfKeyMintVersionFamily.KEYMASTER_HIDL -> {
                (keymasterVersion == null || keymasterVersion == expectedKeymasterVersion) &&
                    (attestationVersion == null || attestationVersion == expectedAttestationVersion)
            }
        }
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
    val vendorApiLevel: Int? = null,
    val vendorApiDetail: String = "Vendor API level was not required.",
    val detail: String,
    val strongBoxManifestPaths: List<String> = emptyList(),
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
            append("vendorApiLevel=")
            append(vendorApiLevel ?: "null")
            append('\n')
            append("vendorApiDetail=")
            append(vendorApiDetail)
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
