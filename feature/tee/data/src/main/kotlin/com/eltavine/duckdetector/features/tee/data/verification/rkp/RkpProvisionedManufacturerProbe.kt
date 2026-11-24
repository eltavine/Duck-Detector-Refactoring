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

package com.eltavine.duckdetector.features.tee.data.verification.rkp

import android.os.Build
import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.core.platform.HiddenSystemProperties
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import java.util.Locale
import org.lsposed.hiddenapibypass.HiddenApiBypass

/**
 * RKP 链的 ProvisioningInfo 扩展（OID 1.3.6.1.4.1.11129.2.1.30）里 map[3] 是 RKP 服务器签发的厂商信息
 * 叶子证书中的 ATTESTATION_ID_MANUFACTURER 由 KeyMint 提供，和 map[3] 来源不同，保留原有的交叉比对
 * 同时比较 Build.MANUFACTURER_FOR_ATTESTATION（不可用时回退到 Build.MANUFACTURER）和 ro.product.manufacturer
 * 有值的来源逐对比较，缺少某个来源时仍比较其余来源，不把未完成的比较当成通过
 * AOSP 允许专用于 attestation 的厂商属性与当前 ro.product.manufacturer 不同，差异本身不能说明哪一方被改动
 *
 * RKP ProvisioningInfo map[3] carries manufacturer information issued by the RKP server
 * The leaf ATTESTATION_ID_MANUFACTURER comes from KeyMint, so retain the original cross-check
 * Also compare Build.MANUFACTURER_FOR_ATTESTATION, falling back to Build.MANUFACTURER, and ro.product.manufacturer
 * Compare every available pair and report missing sources separately
 * A mismatch does not establish which source changed
 */
class RkpProvisionedManufacturerProbe(
    private val readAttestationManufacturer: () -> Result<String?> =
        { readBuildManufacturerForAttestation() },
    private val readProperty: (String) -> Result<String?> = { key -> HiddenSystemProperties.read(key) },
) {

    fun inspect(rkp: TeeRkpState, snapshot: AttestationSnapshot): RkpProvisionedManufacturerResult {
        val systemManufacturer = readProperty(PRODUCT_MANUFACTURER_PROPERTY)
            .getOrNull()
            ?.takeIf(::isUsefulManufacturer)
        val attestationBuildManufacturer = readAttestationManufacturer()
            .getOrNull()
            ?.takeIf(::isUsefulManufacturer)
        val buildManufacturer = selectBuildManufacturer(
            attestationManufacturer = attestationBuildManufacturer,
            manufacturer = Build.MANUFACTURER,
        )
        return compareRkpManufacturers(
            rkp = rkp,
            attestedManufacturer = snapshot.deviceInfo.manufacturer,
            buildManufacturer = buildManufacturer.value,
            systemManufacturer = systemManufacturer,
            buildManufacturerSource = buildManufacturer.source,
        )
    }

    private companion object {
        const val PRODUCT_MANUFACTURER_PROPERTY = "ro.product.manufacturer"
    }
}

/** Reads the hidden @TestApi field without adding process-wide hidden API exemptions. */
internal fun readBuildManufacturerForAttestation(): Result<String?> = runCatching {
    val field = HiddenApiBypass.getStaticFields(Build::class.java)
        .firstOrNull { it.name == "MANUFACTURER_FOR_ATTESTATION" }
        ?: return@runCatching null
    field.isAccessible = true
    field.get(null) as? String
}

private fun isUsefulManufacturer(value: String?): Boolean =
    !value.isNullOrBlank() && !value.equals(Build.UNKNOWN, ignoreCase = true)

internal fun selectBuildManufacturer(
    attestationManufacturer: String?,
    manufacturer: String?,
): BuildManufacturerReference = when {
    attestationManufacturer != null && isUsefulManufacturer(attestationManufacturer) ->
        BuildManufacturerReference(attestationManufacturer, "Build.MANUFACTURER_FOR_ATTESTATION")
    manufacturer != null && isUsefulManufacturer(manufacturer) ->
        BuildManufacturerReference(manufacturer, "Build.MANUFACTURER fallback")
    else -> BuildManufacturerReference(null, "Build manufacturer unavailable")
}

data class BuildManufacturerReference(
    val value: String?,
    val source: String,
)

enum class RkpProvisionedManufacturerAnomalyKind {
    NONE,
    MISMATCH,
    PARTIALLY_EVALUATED,
    UNAVAILABLE,
}

internal fun compareRkpManufacturers(
    rkp: TeeRkpState,
    attestedManufacturer: String?,
    buildManufacturer: String?,
    systemManufacturer: String?,
    buildManufacturerSource: String = "Build.MANUFACTURER_FOR_ATTESTATION",
): RkpProvisionedManufacturerResult {
    val provisioning = rkp.provisioningManufacturer?.takeIf { rkp.serverSigned && it.isNotBlank() }
    val attested = attestedManufacturer?.takeIf(String::isNotBlank)
    val build = buildManufacturer?.takeIf(::isUsefulManufacturer)
    val system = systemManufacturer?.takeIf(::isUsefulManufacturer)
    val sources = listOf(
        "RKP map[3]" to provisioning,
        "ATTESTATION_ID_MANUFACTURER" to attested,
        buildManufacturerSource to build,
        "ro.product.manufacturer" to system,
    )
    val comparisons = buildList {
        for (leftIndex in sources.indices) {
            val (leftSource, leftValue) = sources[leftIndex]
            if (leftValue == null) continue
            for (rightIndex in leftIndex + 1 until sources.size) {
                val (rightSource, rightValue) = sources[rightIndex]
                if (rightValue == null) continue
                add(ManufacturerComparison(
                    leftSource = leftSource,
                    leftValue = leftValue,
                    rightSource = rightSource,
                    rightValue = rightValue,
                    matches = manufacturerNamesAgree(leftValue, rightValue),
                ))
            }
        }
    }
    val unavailableSources = sources.mapNotNull { (source, value) ->
        if (value != null) null
        else if (source == "RKP map[3]" && !rkp.serverSigned) "$source (no authenticated provisioning info)"
        else source
    }
    val kind = when {
        comparisons.any { !it.matches } -> RkpProvisionedManufacturerAnomalyKind.MISMATCH
        comparisons.isEmpty() -> RkpProvisionedManufacturerAnomalyKind.UNAVAILABLE
        unavailableSources.isNotEmpty() -> RkpProvisionedManufacturerAnomalyKind.PARTIALLY_EVALUATED
        else -> RkpProvisionedManufacturerAnomalyKind.NONE
    }
    return RkpProvisionedManufacturerResult(
        probeRan = true,
        anomalyKind = kind,
        provisioningManufacturer = provisioning,
        attestedManufacturer = attested,
        buildManufacturer = build,
        buildManufacturerSource = buildManufacturerSource.takeIf { build != null },
        systemManufacturer = system,
        // certs_issued 只作为报告里的上下文，不参与判定
        // certs_issued is context only and does not affect comparisons
        certsIssued = rkp.certsIssued,
        comparisons = comparisons,
        unavailableSources = unavailableSources,
        detail = buildString {
            if (comparisons.isEmpty()) append("Fewer than two manufacturer sources were available. ")
            comparisons.forEach { comparison ->
                append("${comparison.leftSource}=${comparison.leftValue}, ")
                append("${comparison.rightSource}=${comparison.rightValue}: ")
                append(if (comparison.matches) "matched. " else "mismatched. ")
            }
            if (unavailableSources.isNotEmpty()) {
                append("Not evaluated: ${unavailableSources.joinToString()}. ")
            }
            if (kind == RkpProvisionedManufacturerAnomalyKind.MISMATCH) {
                append("Different manufacturer values do not establish which source changed.")
            }
        }.trim(),
    )
}

/** Manufacturer values may use different names, such as "samsung" and "Samsung Electronics Co., Ltd." */
internal fun manufacturerNamesAgree(provisioningManufacturer: String, systemManufacturer: String): Boolean {
    val left = normalizeManufacturerName(provisioningManufacturer)
    val right = normalizeManufacturerName(systemManufacturer)
    if (left.isEmpty() || right.isEmpty()) return false
    return left == right || left.contains(right) || right.contains(left)
}

private fun normalizeManufacturerName(value: String): String =
    value.uppercase(Locale.US).filter(Char::isLetterOrDigit)

data class ManufacturerComparison(
    val leftSource: String,
    val leftValue: String,
    val rightSource: String,
    val rightValue: String,
    val matches: Boolean,
)

data class RkpProvisionedManufacturerResult(
    val probeRan: Boolean,
    val anomalyKind: RkpProvisionedManufacturerAnomalyKind =
        RkpProvisionedManufacturerAnomalyKind.UNAVAILABLE,
    val provisioningManufacturer: String? = null,
    val attestedManufacturer: String? = null,
    val buildManufacturer: String? = null,
    val buildManufacturerSource: String? = null,
    val systemManufacturer: String? = null,
    val certsIssued: Int? = null,
    val detail: String,
    val comparisons: List<ManufacturerComparison> = emptyList(),
    val unavailableSources: List<String> = emptyList(),
)
