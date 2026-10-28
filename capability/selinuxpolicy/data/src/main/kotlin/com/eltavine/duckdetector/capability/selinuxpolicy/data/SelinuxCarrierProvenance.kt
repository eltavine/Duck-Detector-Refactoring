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

import com.eltavine.duckdetector.core.native.NativePayloadCodec

/** Identifies the code generation and parent that executed doPreload, not the later Binder child. */
internal data class SelinuxCarrierProvenance(
    val preloadPid: Int,
    val appUid: Int,
    val startedNanos: Long,
    val apkPath: String,
    val splitPaths: List<String> = emptyList(),
    val versionCode: Long = 0L,
    val payloadSchemaVersion: Int = SelinuxCarrierBuildMetadata.CURRENT_PAYLOAD_SCHEMA_VERSION,
    val buildRevision: String = "unknown",
)

internal data class SelinuxCarrierExpectedCode(
    val appUid: Int,
    val apkPath: String,
    val splitPaths: List<String> = emptyList(),
    val parentPid: Int? = null,
    val versionCode: Long = 0L,
    val payloadSchemaVersion: Int = SelinuxCarrierBuildMetadata.CURRENT_PAYLOAD_SCHEMA_VERSION,
    val buildRevision: String = "unknown",
)

/** Build metadata is injected by the host APK and travels with the preload that consumed it. */
public object SelinuxCarrierBuildMetadata {
    public const val VERSION_CODE_META_DATA: String = "com.eltavine.duckdetector.PRELOAD_VERSION_CODE"
    public const val BUILD_HASH_META_DATA: String = "com.eltavine.duckdetector.PRELOAD_BUILD_HASH"
    public const val UNKNOWN_BUILD_REVISION: String = "unknown"
    public const val CURRENT_PAYLOAD_SCHEMA_VERSION: Int = 1
}

internal object SelinuxCarrierProvenanceCodec {
    private const val PREFIX = "DUCK_PRELOAD_"
    private const val PARENT_KEY = "DUCK_CARRIER_PARENT_PID="
    private val legacyFields = setOf(
        "DUCK_PRELOAD_PID", "DUCK_PRELOAD_UID", "DUCK_PRELOAD_STARTED_NS", "DUCK_PRELOAD_APK",
    )
    private val currentFields = legacyFields + setOf(
        "DUCK_PRELOAD_VERSION_CODE", "DUCK_PRELOAD_SCHEMA_VERSION", "DUCK_PRELOAD_BUILD_REVISION",
    )

    fun attachCarrierParent(payload: String, parentPid: Int): String =
        payload.trimEnd('\n') + "\n$PARENT_KEY$parentPid\n"

    fun carrierParentPid(payload: String): Int? = payload.lineSequence()
        .filter { it.startsWith(PARENT_KEY) }
        .singleOrNull()
        ?.removePrefix(PARENT_KEY)
        ?.toIntOrNull()
        ?.takeIf { it > 1 }

    fun attach(payload: String, origin: SelinuxCarrierProvenance): String = buildString {
        append("DUCK_PRELOAD_PID=").append(origin.preloadPid).append('\n')
        append("DUCK_PRELOAD_UID=").append(origin.appUid).append('\n')
        append("DUCK_PRELOAD_STARTED_NS=").append(origin.startedNanos).append('\n')
        append("DUCK_PRELOAD_APK=").append(NativePayloadCodec.encodeValue(origin.apkPath)).append('\n')
        append("DUCK_PRELOAD_VERSION_CODE=").append(origin.versionCode).append('\n')
        append("DUCK_PRELOAD_SCHEMA_VERSION=").append(origin.payloadSchemaVersion).append('\n')
        append("DUCK_PRELOAD_BUILD_REVISION=")
            .append(NativePayloadCodec.encodeValue(origin.buildRevision)).append('\n')
        origin.splitPaths.forEach {
            append("DUCK_PRELOAD_SPLIT=").append(NativePayloadCodec.encodeValue(it)).append('\n')
        }
        append(payload)
    }

    fun read(payload: String): SelinuxCarrierProvenance? {
        val fields = mutableMapOf<String, String>()
        val splits = mutableListOf<String>()
        payload.lineSequence().takeWhile { it.startsWith(PREFIX) }.forEach { line ->
            val key = line.substringBefore('=')
            val value = line.substringAfter('=', missingDelimiterValue = "")
            if (key == "DUCK_PRELOAD_SPLIT") {
                splits += NativePayloadCodec.decodeValue(value)
            } else if (fields.put(key, value) != null) {
                return null
            }
        }
        val isLegacy = fields.keys == legacyFields
        if (!isLegacy && fields.keys != currentFields) return null
        val pid = fields["DUCK_PRELOAD_PID"]?.toIntOrNull() ?: return null
        val uid = fields["DUCK_PRELOAD_UID"]?.toIntOrNull() ?: return null
        val started = fields["DUCK_PRELOAD_STARTED_NS"]?.toLongOrNull() ?: return null
        val apk = NativePayloadCodec.decodeValue(fields["DUCK_PRELOAD_APK"].orEmpty())
        val versionCode = if (isLegacy) 0L else fields["DUCK_PRELOAD_VERSION_CODE"]?.toLongOrNull() ?: return null
        val schemaVersion = if (isLegacy) 0 else fields["DUCK_PRELOAD_SCHEMA_VERSION"]?.toIntOrNull() ?: return null
        val buildRevision = if (isLegacy) "unknown" else
            NativePayloadCodec.decodeValue(fields["DUCK_PRELOAD_BUILD_REVISION"].orEmpty())
        if (pid <= 0 || uid < 0 || started <= 0 || apk.isBlank() || versionCode < 0 || schemaVersion < 0 ||
            buildRevision.isBlank() || splits.any(String::isBlank)) return null
        return SelinuxCarrierProvenance(
            preloadPid = pid,
            appUid = uid,
            startedNanos = started,
            apkPath = apk,
            splitPaths = splits,
            versionCode = versionCode,
            payloadSchemaVersion = schemaVersion,
            buildRevision = buildRevision,
        )
    }

    /** A reused parent is legitimate only while it still runs the exact same APK generation. */
    fun mismatch(
        origin: SelinuxCarrierProvenance?,
        expected: SelinuxCarrierExpectedCode,
        nowNanos: Long,
    ): String? = when {
        origin == null -> "App Zygote preload provenance unavailable."
        origin.appUid != expected.appUid -> "App Zygote preload UID mismatch."
        origin.apkPath != expected.apkPath || origin.splitPaths != expected.splitPaths ->
            "App Zygote preload APK generation mismatch."
        origin.payloadSchemaVersion != expected.payloadSchemaVersion ->
            "App Zygote preload schema mismatch."
        origin.versionCode > 0 && expected.versionCode > 0 && origin.versionCode != expected.versionCode ->
            "App Zygote preload version code mismatch."
        origin.buildRevision != "unknown" && expected.buildRevision != "unknown" &&
            origin.buildRevision != expected.buildRevision -> "App Zygote preload build revision mismatch."
        expected.parentPid != null && origin.preloadPid != expected.parentPid ->
            "App Zygote preload parent PID mismatch."
        nowNanos <= 0 || origin.startedNanos > nowNanos ->
            "App Zygote preload timestamp invalid."
        else -> null
    }
}
