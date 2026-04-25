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

package com.eltavine.duckdetector.features.bootloader.data.rules

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory

data class BootloaderPropertySpec(
    val property: String,
    val description: String,
    val category: SystemPropertyCategory,
)

object BootloaderCatalog {

    const val FLASH_LOCKED = "ro.boot.flash.locked"
    const val VERIFIED_BOOT_STATE = "ro.boot.verifiedbootstate"
    const val SECURE_BOOT = "ro.boot.secureboot"
    const val DEBUGGABLE = "ro.debuggable"
    const val SECURE = "ro.secure"
    const val WARRANTY_BIT = "ro.boot.warranty_bit"
    const val WARRANTY_BIT_ALT = "ro.warranty_bit"
    const val KNOX_STATE = "ro.boot.knox.state"
    const val OEM_UNLOCK_SUPPORTED = "ro.oem_unlock_supported"
    const val VBMETA_DEVICE_STATE = "ro.boot.vbmeta.device_state"
    const val VERITYMODE = "ro.boot.veritymode"
    const val VBMETA_HASH_ALG = "ro.boot.vbmeta.hash_alg"
    const val VBMETA_SIZE = "ro.boot.vbmeta.size"
    const val VBMETA_DIGEST = "ro.boot.vbmeta.digest"
    const val AVB_VERSION = "ro.boot.avb_version"
    const val VBMETA_INVALIDATE = "ro.boot.vbmeta.invalidate_on_error"
    const val PARTITION_SYSTEM_VERIFIED = "partition.system.verified"
    const val PARTITION_VENDOR_VERIFIED = "partition.vendor.verified"
    const val PARTITION_PRODUCT_VERIFIED = "partition.product.verified"
    const val PARTITION_SYSTEM_EXT_VERIFIED = "partition.system_ext.verified"
    const val PARTITION_ODM_VERIFIED = "partition.odm.verified"

    val properties = listOf(
        BootloaderPropertySpec(
            FLASH_LOCKED,
            "Bootloader lock status",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            VERIFIED_BOOT_STATE,
            "Verified Boot state",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            SECURE_BOOT,
            "Secure boot flag",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            DEBUGGABLE,
            "Debuggable build flag",
            SystemPropertyCategory.SECURITY_CORE
        ),
        BootloaderPropertySpec(SECURE, "Secure build flag", SystemPropertyCategory.SECURITY_CORE),
        BootloaderPropertySpec(
            WARRANTY_BIT,
            "Samsung warranty e-fuse",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            WARRANTY_BIT_ALT,
            "Samsung warranty e-fuse (alt)",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            KNOX_STATE,
            "Samsung Knox state",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            OEM_UNLOCK_SUPPORTED,
            "OEM unlock support",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            VBMETA_DEVICE_STATE,
            "VBMeta device state",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(VERITYMODE, "dm-verity mode", SystemPropertyCategory.VERIFIED_BOOT),
        BootloaderPropertySpec(
            VBMETA_HASH_ALG,
            "VBMeta hash algorithm",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(VBMETA_SIZE, "VBMeta size", SystemPropertyCategory.VERIFIED_BOOT),
        BootloaderPropertySpec(
            VBMETA_DIGEST,
            "VBMeta digest",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(AVB_VERSION, "AVB version", SystemPropertyCategory.VERIFIED_BOOT),
        BootloaderPropertySpec(
            VBMETA_INVALIDATE,
            "VBMeta invalidate-on-error",
            SystemPropertyCategory.VERIFIED_BOOT
        ),
        BootloaderPropertySpec(
            PARTITION_SYSTEM_VERIFIED,
            "System partition dm-verity",
            SystemPropertyCategory.PARTITION_VERITY
        ),
        BootloaderPropertySpec(
            PARTITION_VENDOR_VERIFIED,
            "Vendor partition dm-verity",
            SystemPropertyCategory.PARTITION_VERITY
        ),
        BootloaderPropertySpec(
            PARTITION_PRODUCT_VERIFIED,
            "Product partition dm-verity",
            SystemPropertyCategory.PARTITION_VERITY
        ),
        BootloaderPropertySpec(
            PARTITION_SYSTEM_EXT_VERIFIED,
            "System_ext partition dm-verity",
            SystemPropertyCategory.PARTITION_VERITY
        ),
        BootloaderPropertySpec(
            PARTITION_ODM_VERIFIED,
            "ODM partition dm-verity",
            SystemPropertyCategory.PARTITION_VERITY
        ),
    )
}
