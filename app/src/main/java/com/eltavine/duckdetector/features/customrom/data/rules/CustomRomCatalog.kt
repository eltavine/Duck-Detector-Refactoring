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

package com.eltavine.duckdetector.features.customrom.data.rules

data class CustomRomPropertySignature(
    val property: String,
    val romName: String,
)

data class CustomRomBuildFieldSignature(
    val keyword: String,
    val romName: String,
)

data class CustomRomPackageSignature(
    val packageName: String,
    val appName: String,
    val romName: String,
)

data class CustomRomServiceSignature(
    val serviceName: String,
    val romName: String,
)

data class CustomRomReflectionTarget(
    val className: String,
    val fieldName: String,
    val romName: String,
)

data class CustomRomPlatformFileSignature(
    val path: String,
    val romName: String,
)

object CustomRomCatalog {

    val propertySignatures = listOf(
        CustomRomPropertySignature("ro.modversion", "Custom ROM"),
        CustomRomPropertySignature("ro.cm.version", "LineageOS"),
        CustomRomPropertySignature("ro.lineage.version", "LineageOS"),
        CustomRomPropertySignature("ro.resurrection.version", "ResurrectionRemix"),
        CustomRomPropertySignature("ro.pa.version", "ParanoidAndroid"),
        CustomRomPropertySignature("ro.aospa.version", "ParanoidAndroid"),
        CustomRomPropertySignature("ro.crdroid.version", "crDroid"),
        CustomRomPropertySignature("ro.pixelexperience.version", "PixelExperience"),
        CustomRomPropertySignature("ro.evolution.version", "Evolution-X"),
        CustomRomPropertySignature("ro.havoc.version", "Havoc-OS"),
    )

    val buildFieldKeywords = listOf(
        CustomRomBuildFieldSignature("lineage", "LineageOS"),
        CustomRomBuildFieldSignature("crdroid", "crDroid"),
        CustomRomBuildFieldSignature("aospa", "ParanoidAndroid"),
        CustomRomBuildFieldSignature("paranoid", "ParanoidAndroid"),
        CustomRomBuildFieldSignature("pixelexperience", "PixelExperience"),
        CustomRomBuildFieldSignature("evolution", "Evolution-X"),
        CustomRomBuildFieldSignature("omnirom", "OmniROM"),
        CustomRomBuildFieldSignature("protonaosp", "ProtonAOSP"),
        CustomRomBuildFieldSignature("havoc", "Havoc-OS"),
        CustomRomBuildFieldSignature("resurrection", "ResurrectionRemix"),
    )

    val packageSignatures = listOf(
        CustomRomPackageSignature("org.lineageos.jelly", "Jelly Browser", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.aperture", "Aperture Camera", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.recorder", "Recorder", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.etar", "Etar Calendar", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.twelve", "Twelve Music", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.glimpse", "Glimpse Gallery", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.updater", "Updater", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.lineageparts", "LineageParts", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.profiles", "Profiles", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.backgrounds", "Backgrounds", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.camelot", "Camelot PDF", "LineageOS"),
        CustomRomPackageSignature("org.lineageos.lineagesettings", "LineageSettings", "LineageOS"),
        CustomRomPackageSignature("com.crdroid.settings", "crDroid Settings", "crDroid"),
        CustomRomPackageSignature("com.crdroid.updater", "crDroid Updater", "crDroid"),
        CustomRomPackageSignature("com.crdroid.ltpo.oplus", "crDroid LTPO", "crDroid"),
        CustomRomPackageSignature("co.aospa.sense", "Face Unlock", "ParanoidAndroid"),
        CustomRomPackageSignature("co.aospa.dolby.oplus", "Dolby Atmos", "ParanoidAndroid"),
        CustomRomPackageSignature("org.protonaosp.columbus", "Columbus Service", "ProtonAOSP"),
        CustomRomPackageSignature("org.protonaosp.deviceconfig", "Device Config", "ProtonAOSP"),
        CustomRomPackageSignature("org.omnirom.omnijaws", "OmniJaws Weather", "OmniROM"),
        CustomRomPackageSignature("org.omnirom.omnistyle", "OmniStyle", "OmniROM"),
        CustomRomPackageSignature("io.chaldeaprjkt.gamespace", "GameSpace", "Other Custom ROM"),
    )

    val specificServices = listOf(
        CustomRomServiceSignature("lineageglobalactions", "LineageOS"),
        CustomRomServiceSignature("lineagehardware", "LineageOS"),
        CustomRomServiceSignature("lineagehealth", "LineageOS"),
        CustomRomServiceSignature("lineagelivedisplay", "LineageOS"),
        CustomRomServiceSignature("lineagetrust", "LineageOS"),
        CustomRomServiceSignature("profile", "LineageOS"),
        CustomRomServiceSignature("vendor.lineage.health.IChargingControl/default", "LineageOS"),
        CustomRomServiceSignature("vendor.lineage.health.IFastCharge/default", "LineageOS"),
        CustomRomServiceSignature(
            "vendor.lineage.livedisplay.IPictureAdjustment/default",
            "LineageOS"
        ),
        CustomRomServiceSignature("vendor.lineage.touch.ITouchscreenGesture/default", "LineageOS"),
        CustomRomServiceSignature("vendor.lineage.livedisplay.IDisplayModes/default", "LineageOS"),
    )

    val servicePatterns = listOf(
        "lineage" to "LineageOS",
        "crdroid" to "crDroid",
        "aospa" to "ParanoidAndroid",
        "pixelexperience" to "PixelExperience",
        "omnirom" to "OmniROM",
        "protonaosp" to "ProtonAOSP",
    )

    val reflectionTargets = listOf(
        CustomRomReflectionTarget(
            className = "android.content.res.AssetManager",
            fieldName = "LINEAGE_APK_PATH",
            romName = "LineageOS",
        ),
    )

    val platformFileSignatures = listOf(
        CustomRomPlatformFileSignature(
            path = "/system/framework/org.lineageos.platform-res.apk",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/oat/arm64/org.lineageos.platform.vdex",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/oat/arm64/org.lineageos.platform.odex",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/oat/arm/org.lineageos.platform.vdex",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/oat/arm/org.lineageos.platform.odex",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/system_ext/framework/org.lineageos.platform.jar",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/crdroid-res.apk",
            romName = "crDroid",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/org.pixelexperience.platform-res.apk",
            romName = "PixelExperience",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/org.evolution.framework-res.apk",
            romName = "Evolution-X",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/co.aospa.framework-res.apk",
            romName = "ParanoidAndroid",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/org.protonaosp.framework-res.apk",
            romName = "ProtonAOSP",
        ),
        CustomRomPlatformFileSignature(
            path = "/system/framework/org.omnirom.platform-res.apk",
            romName = "OmniROM",
        ),
        CustomRomPlatformFileSignature(
            path = "/product/framework/org.lineageos.platform-res.apk",
            romName = "LineageOS",
        ),
        CustomRomPlatformFileSignature(
            path = "/product/overlay/LineageSettingsProvider.apk",
            romName = "LineageOS",
        ),
    )

    val buildFields = listOf(
        "Build.DISPLAY",
        "Build.FINGERPRINT",
        "Build.HOST",
    )
}
