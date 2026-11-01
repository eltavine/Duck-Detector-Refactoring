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

package com.eltavine.duckdetector.features.rootmanagers.data.probes.canary

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryTarget
import java.io.File

/** Validates the independent shared-UID rejection boundary before any installer session exists. */
internal class InstallerCanaryArchive(private val context: Context) {
    val missingGroup: String get() = "${context.packageName}.installer_canary.missing"

    @Suppress("DEPRECATION")
    fun validate(file: File) {
        val pm = context.packageManager
        val flags = PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_PERMISSIONS or
            PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or
            PackageManager.GET_SERVICES or PackageManager.GET_PROVIDERS
        val installed = pm.getPackageInfo(context.packageName, flags)
        val archive = requireNotNull(pm.getPackageArchiveInfo(file.path, flags)) { "Canary APK could not be parsed" }
        val hostInfo = requireNotNull(installed.applicationInfo)
        val info = requireNotNull(archive.applicationInfo)
        require(installed.sharedUserId == null) { "Shared-UID hosts are unsupported" }
        require(hostInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0) { "System application hosts are unsupported" }
        require(archive.packageName == context.packageName) { "Canary package differs from host" }
        require(archive.longVersionCode > installed.longVersionCode) { "Canary version must exceed the installed version" }
        require(info.minSdkVersion == 33 && info.targetSdkVersion == hostInfo.targetSdkVersion && info.targetSdkVersion >= 33)
        require(info.flags and ApplicationInfo.FLAG_HAS_CODE == 0) { "Canary must contain no executable application code" }
        require(archive.sharedUserId == "android.uid.system") { "Shared-UID rejection boundary is missing" }
        val own = requireNotNull(installed.signingInfo).apkContentsSigners.toSet()
        val candidate = requireNotNull(archive.signingInfo).apkContentsSigners.toSet()
        require(own.isNotEmpty() && own == candidate) { "Canary signer differs from installed host" }
        // Shared-UID continuity rejects updates; signature separation also rejects a fresh install.
        val platform = pm.getPackageInfo("android", PackageManager.GET_SIGNING_CERTIFICATES)
        val platformUid = requireNotNull(platform.applicationInfo).uid
        require(platform.sharedUserId == "android.uid.system" && platformUid % 100_000 == 1000) {
            "The platform shared-UID rejection boundary could not be established"
        }
        val platformSigning = requireNotNull(platform.signingInfo)
        val platformCertificates = platformSigning.apkContentsSigners.toSet() +
            platformSigning.signingCertificateHistory.orEmpty().toSet()
        val hostCertificates = own + requireNotNull(installed.signingInfo).signingCertificateHistory.orEmpty().toSet()
        // Query the shared UID's merged signing history, including rotations of other UID members.
        // The framework certificate is a positive control for visibility of this UID query.
        fun uidHasCertificate(certificate: android.content.pm.Signature): Boolean =
            pm.hasSigningCertificate(platformUid, certificate.toByteArray(), PackageManager.CERT_INPUT_RAW_X509)
        require(platformCertificates.isNotEmpty() && platformCertificates.all(::uidHasCertificate) &&
            hostCertificates.none(::uidHasCertificate) &&
            pm.checkSignatures(hostInfo.uid, platformUid) == PackageManager.SIGNATURE_NO_MATCH) {
            "Platform-signing hosts are unsupported"
        }

        val permission = requireNotNull(archive.permissions).single()
        require(permission.name == InstallerCanaryTarget.PERMISSION && permission.group == missingGroup)
        require(archive.activities.isNullOrEmpty() && archive.receivers.isNullOrEmpty() &&
            archive.services.isNullOrEmpty() && archive.providers.isNullOrEmpty()) { "Canary must declare no application components" }
    }
}
