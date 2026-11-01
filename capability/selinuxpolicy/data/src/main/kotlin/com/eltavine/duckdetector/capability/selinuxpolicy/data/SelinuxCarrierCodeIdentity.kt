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

package com.eltavine.duckdetector.capability.selinuxpolicy.data

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

/** Cross-checks what the current PackageManager expects against the App-Zygote preload origin. */
internal object SelinuxCarrierCodeIdentity {
    fun provenanceFailureReason(
        raw: String,
        codeAtBind: SelinuxCarrierExpectedCode?,
        codeAtReply: SelinuxCarrierExpectedCode?,
        nowNanos: Long,
    ): String? {
        val parsed = SelinuxContextValidityBridge().parse(raw)
        if (codeAtBind == null || codeAtReply == null) return "SELinux carrier APK identity unavailable."
        if (codeAtBind != codeAtReply) return "SELinux carrier APK changed during collection."
        val origin = SelinuxCarrierProvenanceCodec.read(raw)
        if (origin == null) return parsed.failureReason ?: "App Zygote preload provenance unavailable."
        return SelinuxCarrierProvenanceCodec.mismatch(origin, codeAtReply, nowNanos)
    }

    fun readExpectedCode(
        context: Context,
        serviceClass: Class<out Service>,
    ): SelinuxCarrierExpectedCode? = runCatching {
        val component = ComponentName(context, serviceClass)
        val info = context.packageManager.getServiceInfo(component, 0).applicationInfo
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
        val appInfoWithMetadata = context.packageManager.getApplicationInfo(
            context.packageName,
            PackageManager.GET_META_DATA,
        )
        val metadata = appInfoWithMetadata.metaData
        val declaredVersion = metadata?.get(SelinuxCarrierBuildMetadata.VERSION_CODE_META_DATA)
            ?.toString()?.toLongOrNull() ?: 0L
        // SDK hosts do not necessarily embed Duck's manifest metadata. Only claim a version
        // match when the host explicitly supplies one, and verify that it agrees with PM.
        require(declaredVersion <= 0L || declaredVersion == packageInfo.longVersionCode) {
            "Manifest preload version does not match installed package version."
        }
        val buildRevision = metadata?.get(SelinuxCarrierBuildMetadata.BUILD_HASH_META_DATA)
            ?.toString()?.takeIf { it.isNotBlank() }
            ?: SelinuxCarrierBuildMetadata.UNKNOWN_BUILD_REVISION
        SelinuxCarrierExpectedCode(
            appUid = info.uid,
            apkPath = info.sourceDir.orEmpty(),
            splitPaths = info.splitSourceDirs?.toList().orEmpty(),
            versionCode = declaredVersion,
            payloadSchemaVersion = SelinuxCarrierBuildMetadata.CURRENT_PAYLOAD_SCHEMA_VERSION,
            buildRevision = buildRevision,
        )
    }.getOrNull()
}
