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

package com.eltavine.duckdetector.features.systemproperties.data.rules

import com.eltavine.duckdetector.features.systemproperties.domain.SystemPropertyCategory

data class SystemPropertyRule(
    val property: String,
    val description: String,
    val category: SystemPropertyCategory,
    val dangerousValues: List<String> = emptyList(),
    val warningValues: List<String> = emptyList(),
    val expectedSafeValue: String? = null,
)

object SystemPropertiesCatalog {

    val rules = listOf(
        SystemPropertyRule(
            property = "ro.secure",
            description = "ADB root access control",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("0"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "ro.debuggable",
            description = "System debuggability",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("1"),
            expectedSafeValue = "0",
        ),
        SystemPropertyRule(
            property = "ro.adb.secure",
            description = "ADB authentication",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("0"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "service.adb.root",
            description = "ADB running as root",
            category = SystemPropertyCategory.SECURITY_CORE,
            expectedSafeValue = "0",
        ),
        SystemPropertyRule(
            property = "persist.sys.usb.config",
            description = "USB debug configuration",
            category = SystemPropertyCategory.SECURITY_CORE,
            warningValues = listOf("adb", "mtp,adb", "ptp,adb"),
            expectedSafeValue = "mtp",
        ),
        SystemPropertyRule(
            property = "ro.boot.selinux",
            description = "SELinux boot status",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("disabled", "permissive"),
            expectedSafeValue = "enforcing",
        ),
        SystemPropertyRule(
            property = "ro.build.selinux",
            description = "SELinux build status",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("0"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "ro.boot.verifiedbootstate",
            description = "Verified boot state",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("orange", "red"),
            warningValues = listOf("yellow"),
            expectedSafeValue = "green",
        ),
        SystemPropertyRule(
            property = "ro.boot.flash.locked",
            description = "Bootloader lock status",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("0", "false"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "ro.boot.veritymode",
            description = "dm-verity mode",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("disabled", "logging"),
            expectedSafeValue = "enforcing",
        ),
        SystemPropertyRule(
            property = "ro.boot.vbmeta.device_state",
            description = "VBMeta device state",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("unlocked"),
            expectedSafeValue = "locked",
        ),
        SystemPropertyRule(
            property = "ro.boot.vbmeta.hash_alg",
            description = "VBMeta hash algorithm",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            expectedSafeValue = "sha256",
        ),
        SystemPropertyRule(
            property = "ro.boot.avb_version",
            description = "AVB version",
            category = SystemPropertyCategory.VERIFIED_BOOT,
        ),
        SystemPropertyRule(
            property = "ro.boot.vbmeta.invalidate_on_error",
            description = "VBMeta invalidate on error",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            warningValues = listOf("no", "0"),
            expectedSafeValue = "yes",
        ),
        SystemPropertyRule(
            property = "partition.system.verified",
            description = "System partition dm-verity",
            category = SystemPropertyCategory.PARTITION_VERITY,
            dangerousValues = listOf("0"),
            warningValues = listOf("2"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "partition.vendor.verified",
            description = "Vendor partition dm-verity",
            category = SystemPropertyCategory.PARTITION_VERITY,
            dangerousValues = listOf("0"),
            warningValues = listOf("2"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "partition.product.verified",
            description = "Product partition dm-verity",
            category = SystemPropertyCategory.PARTITION_VERITY,
            dangerousValues = listOf("0"),
            warningValues = listOf("2"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "partition.system_ext.verified",
            description = "System_ext partition dm-verity",
            category = SystemPropertyCategory.PARTITION_VERITY,
            dangerousValues = listOf("0"),
            warningValues = listOf("2"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "partition.odm.verified",
            description = "ODM partition dm-verity",
            category = SystemPropertyCategory.PARTITION_VERITY,
            dangerousValues = listOf("0"),
            warningValues = listOf("2"),
            expectedSafeValue = "1",
        ),
        SystemPropertyRule(
            property = "ro.build.type",
            description = "Build type",
            category = SystemPropertyCategory.BUILD_PROFILE,
            dangerousValues = listOf("eng", "userdebug"),
            expectedSafeValue = "user",
        ),
        SystemPropertyRule(
            property = "ro.build.tags",
            description = "Build signature tags",
            category = SystemPropertyCategory.BUILD_PROFILE,
            dangerousValues = listOf("test-keys", "dev-keys"),
            expectedSafeValue = "release-keys",
        ),
        SystemPropertyRule(
            property = "ro.build.flavor",
            description = "Build flavor",
            category = SystemPropertyCategory.BUILD_PROFILE,
            dangerousValues = listOf("eng", "userdebug"),
        ),
        SystemPropertyRule(
            property = "ro.crypto.state",
            description = "Device encryption state",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("unencrypted"),
            expectedSafeValue = "encrypted",
        ),
        SystemPropertyRule(
            property = "sys.oem_unlock_allowed",
            description = "OEM unlock allowed",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            warningValues = listOf("1", "true"),
            expectedSafeValue = "0",
        ),
        SystemPropertyRule(
            property = "ro.oem_unlock_supported",
            description = "OEM unlock supported",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            warningValues = listOf("1", "true"),
        ),
        SystemPropertyRule(
            property = "init.svc.magisk_daemon",
            description = "Magisk daemon service",
            category = SystemPropertyCategory.ROOT_RUNTIME,
            dangerousValues = listOf("running", "restarting"),
        ),
        SystemPropertyRule(
            property = "init.svc.magisk_service",
            description = "Magisk service",
            category = SystemPropertyCategory.ROOT_RUNTIME,
            dangerousValues = listOf("running", "restarting"),
        ),
        SystemPropertyRule(
            property = "ro.magisk.hide",
            description = "Magisk Hide status",
            category = SystemPropertyCategory.ROOT_RUNTIME,
            dangerousValues = listOf("1", "true"),
        ),
        SystemPropertyRule(
            property = "persist.sys.development_settings_enabled",
            description = "Developer options enabled",
            category = SystemPropertyCategory.SECURITY_CORE,
            warningValues = listOf("1", "true"),
        ),
        SystemPropertyRule(
            property = "ro.modversion",
            description = "Custom ROM mod version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.cm.version",
            description = "CyanogenMod or LineageOS version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.lineage.version",
            description = "LineageOS version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.resurrection.version",
            description = "Resurrection Remix version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.pa.version",
            description = "Paranoid Android version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.crdroid.version",
            description = "crDroid version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.pixelexperience.version",
            description = "Pixel Experience version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.evolution.version",
            description = "Evolution X version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.havoc.version",
            description = "Havoc-OS version",
            category = SystemPropertyCategory.CUSTOM_ROM,
            dangerousValues = listOf("*"),
        ),
        SystemPropertyRule(
            property = "ro.allow.mock.location",
            description = "Mock location allowed",
            category = SystemPropertyCategory.SECURITY_CORE,
            dangerousValues = listOf("1", "true"),
            expectedSafeValue = "0",
        ),
        SystemPropertyRule(
            property = "ro.boot.warranty_bit",
            description = "Warranty status (Samsung)",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("1"),
            expectedSafeValue = "0",
        ),
        SystemPropertyRule(
            property = "ro.warranty_bit",
            description = "Warranty void status",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("1"),
            expectedSafeValue = "0",
        ),
        SystemPropertyRule(
            property = "ro.boot.knox.state",
            description = "Knox state",
            category = SystemPropertyCategory.VERIFIED_BOOT,
            dangerousValues = listOf("TRIPPED", "0x1"),
            expectedSafeValue = "NORMAL",
        ),
    )

    val infoProperties = listOf(
        "ro.build.fingerprint",
        "ro.build.display.id",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.product.model",
        "ro.product.brand",
        "ro.product.device",
        "ro.product.manufacturer",
        "ro.hardware",
        "ro.bootimage.build.fingerprint",
        "ro.vendor.build.fingerprint",
        "ro.system.build.fingerprint",
        "ro.boot.vbmeta.hash_alg",
        "ro.boot.vbmeta.size",
        "ro.boot.vbmeta.digest",
        "ro.boot.avb_version",
    )

    val suspiciousFingerprintPatterns = listOf(
        "test-keys",
        "dev-keys",
        "userdebug",
        "/eng/",
        "generic",
        "unknown",
        "Android-x86",
        "vbox",
        "genymotion",
    )
}
