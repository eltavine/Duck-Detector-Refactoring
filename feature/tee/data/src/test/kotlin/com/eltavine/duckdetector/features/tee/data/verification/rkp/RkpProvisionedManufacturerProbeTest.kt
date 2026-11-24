package com.eltavine.duckdetector.features.tee.data.verification.rkp

import com.eltavine.duckdetector.capability.attestation.data.AttestationSnapshot
import com.eltavine.duckdetector.capability.attestation.data.AttestedDeviceInfo
import com.eltavine.duckdetector.capability.attestation.domain.TeeTier
import com.eltavine.duckdetector.features.tee.domain.TeeRkpState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RkpProvisionedManufacturerProbeTest {

    @Test
    fun `authenticated RKP manufacturer is compared with attestation and property values`() {
        var requestedProperty: String? = null
        val probe = RkpProvisionedManufacturerProbe(
            readAttestationManufacturer = { Result.success("Samsung") },
            readProperty = { key ->
                requestedProperty = key
                Result.success("samsung")
            },
        )

        val result = probe.inspect(
            TeeRkpState(serverSigned = true, provisioningManufacturer = "Samsung"),
            snapshot("samsung"),
        )

        assertEquals("ro.product.manufacturer", requestedProperty)
        assertEquals(RkpProvisionedManufacturerAnomalyKind.NONE, result.anomalyKind)
        assertEquals("samsung", result.systemManufacturer)
        assertEquals("samsung", result.attestedManufacturer)
        assertEquals("Samsung", result.buildManufacturer)
        assertEquals("Build.MANUFACTURER_FOR_ATTESTATION", result.buildManufacturerSource)
        assertEquals(6, result.comparisons.size)
    }

    @Test
    fun `every available pair is compared and mismatching pair is named`() {
        val result = compareRkpManufacturers(
            rkp = TeeRkpState(serverSigned = true, provisioningManufacturer = "Samsung"),
            attestedManufacturer = "Samsung",
            buildManufacturer = "Samsung",
            systemManufacturer = "Xiaomi",
        )

        assertEquals(RkpProvisionedManufacturerAnomalyKind.MISMATCH, result.anomalyKind)
        assertEquals(6, result.comparisons.size)
        assertEquals(3, result.comparisons.count { !it.matches })
        assertTrue(result.detail.contains("ro.product.manufacturer=Xiaomi"))
        assertTrue(result.detail.contains("ATTESTATION_ID_MANUFACTURER=Samsung"))
    }

    @Test
    fun `spelling differences allowed by previous check still match`() {
        assertTrue(manufacturerNamesAgree("samsung", "Samsung Electronics Co., Ltd."))
    }

    @Test
    fun `attestation manufacturer takes priority with public build fallback`() {
        assertEquals(
            BuildManufacturerReference("Attestation Brand", "Build.MANUFACTURER_FOR_ATTESTATION"),
            selectBuildManufacturer("Attestation Brand", "Product Brand"),
        )
        assertEquals(
            BuildManufacturerReference("Product Brand", "Build.MANUFACTURER fallback"),
            selectBuildManufacturer("unknown", "Product Brand"),
        )
    }

    @Test
    fun `missing RKP value leaves attestation and property comparison active`() {
        val result = compareRkpManufacturers(
            rkp = TeeRkpState(serverSigned = false, provisioningManufacturer = "untrusted"),
            attestedManufacturer = "Samsung",
            buildManufacturer = "Samsung",
            systemManufacturer = "Samsung",
        )

        assertEquals(RkpProvisionedManufacturerAnomalyKind.PARTIALLY_EVALUATED, result.anomalyKind)
        assertEquals(3, result.comparisons.size)
        assertTrue(result.comparisons.all { it.matches })
        assertTrue(result.unavailableSources.single().contains("RKP map[3]"))
    }

    @Test
    fun `property read failure leaves other available pair comparison active`() {
        val probe = RkpProvisionedManufacturerProbe(
            readAttestationManufacturer = { Result.success("Samsung") },
            readProperty = { Result.failure(IllegalStateException("hidden API")) },
        )
        val result = probe.inspect(
            TeeRkpState(serverSigned = true, provisioningManufacturer = "Samsung"),
            snapshot("Samsung"),
        )

        assertEquals(RkpProvisionedManufacturerAnomalyKind.PARTIALLY_EVALUATED, result.anomalyKind)
        assertEquals(3, result.comparisons.size)
        assertTrue(result.unavailableSources.contains("ro.product.manufacturer"))
    }

    private fun snapshot(manufacturer: String?) = AttestationSnapshot(
        tier = TeeTier.STRONGBOX,
        attestationVersion = 400,
        keymasterVersion = 400,
        attestationTier = TeeTier.STRONGBOX,
        keymasterTier = TeeTier.STRONGBOX,
        challengeVerified = true,
        challengeSummary = null,
        rootOfTrust = null,
        osVersion = null,
        osPatchLevel = null,
        vendorPatchLevel = null,
        bootPatchLevel = null,
        deviceInfo = AttestedDeviceInfo(manufacturer = manufacturer),
        rawCertificates = emptyList(),
        displayCertificates = emptyList(),
    )
}
