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
)

internal data class SelinuxCarrierExpectedCode(
    val appUid: Int,
    val apkPath: String,
    val splitPaths: List<String> = emptyList(),
    val parentPid: Int? = null,
)

internal object SelinuxCarrierProvenanceCodec {
    private const val PREFIX = "DUCK_PRELOAD_"
    private const val PARENT_KEY = "DUCK_CARRIER_PARENT_PID="

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
        if (fields.keys != setOf(
                "DUCK_PRELOAD_PID", "DUCK_PRELOAD_UID", "DUCK_PRELOAD_STARTED_NS", "DUCK_PRELOAD_APK",
            )) return null
        val pid = fields["DUCK_PRELOAD_PID"]?.toIntOrNull() ?: return null
        val uid = fields["DUCK_PRELOAD_UID"]?.toIntOrNull() ?: return null
        val started = fields["DUCK_PRELOAD_STARTED_NS"]?.toLongOrNull() ?: return null
        val apk = NativePayloadCodec.decodeValue(fields["DUCK_PRELOAD_APK"].orEmpty())
        if (pid <= 0 || uid < 0 || started <= 0 || apk.isBlank() || splits.any(String::isBlank)) return null
        return SelinuxCarrierProvenance(pid, uid, started, apk, splits)
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
        expected.parentPid != null && origin.preloadPid != expected.parentPid ->
            "App Zygote preload parent PID mismatch."
        nowNanos <= 0 || origin.startedNanos > nowNanos ->
            "App Zygote preload timestamp invalid."
        else -> null
    }
}
