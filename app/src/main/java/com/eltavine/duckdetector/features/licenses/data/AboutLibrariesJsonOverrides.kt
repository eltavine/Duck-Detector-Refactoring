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

package com.eltavine.duckdetector.features.licenses.data

import org.json.JSONArray
import org.json.JSONObject

object AboutLibrariesJsonOverrides {
    private const val SOTER_UNIQUE_ID = "com.github.Tencent.soter:soter-wrapper"
    private const val SOTER_LICENSE_PAGE =
        "https://github.com/Tencent/soter/blob/master/LICENSE"
    private const val SOTER_LICENSE_ID = "BSD-3-Clause"

    private const val HIDDEN_API_BYPASS_UNIQUE_ID =
        "org.lsposed.hiddenapibypass:hiddenapibypass"
    private const val HIDDEN_API_BYPASS_LICENSE_PAGE =
        "https://github.com/LSPosed/AndroidHiddenApiBypass/blob/main/LICENSE"
    private const val HIDDEN_API_BYPASS_LICENSE_ID = "Apache-2.0"
    private const val FIREBASE_ANDROID_SDK_REPO =
        "https://github.com/firebase/firebase-android-sdk"
    private const val ABOUT_LIBRARIES_VERSION = "14.0.0"
    private const val BOUNCY_CASTLE_VERSION = "1.84"
    private const val BOUNCY_CASTLE_DESCRIPTION =
        "The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms. This jar contains the JCA/JCE provider and low-level API for the BC Java version 1.84 for Java 1.8 and later."

    private val libraryOverrides = mapOf(
        SOTER_UNIQUE_ID to LibraryOverride(
            name = "Tencent Soter",
            description = "Upstream LICENSE states Tencent Soter source and binary releases are under the BSD 3-Clause License.",
            website = SOTER_LICENSE_PAGE,
            licenses = listOf(SOTER_LICENSE_ID),
        ),
        HIDDEN_API_BYPASS_UNIQUE_ID to LibraryOverride(
            name = "Android HiddenApiBypass",
            description = "Utilities from LSPosed's AndroidHiddenApiBypass project for accessing hidden Android APIs under the Apache License 2.0.",
            website = HIDDEN_API_BYPASS_LICENSE_PAGE,
            licenses = listOf(HIDDEN_API_BYPASS_LICENSE_ID),
        ),
        "com.mikepenz:aboutlibraries-compose-core" to LibraryOverride(
            artifactVersion = ABOUT_LIBRARIES_VERSION,
        ),
        "com.mikepenz:aboutlibraries-compose-m3" to LibraryOverride(
            artifactVersion = ABOUT_LIBRARIES_VERSION,
        ),
        "com.mikepenz:aboutlibraries-core" to LibraryOverride(
            artifactVersion = ABOUT_LIBRARIES_VERSION,
        ),
        "org.bouncycastle:bcprov-jdk18on" to LibraryOverride(
            artifactVersion = BOUNCY_CASTLE_VERSION,
            description = BOUNCY_CASTLE_DESCRIPTION,
        ),
        "com.google.android.datatransport:transport-api" to LibraryOverride(
            website = FIREBASE_ANDROID_SDK_REPO,
        ),
        "com.google.android.datatransport:transport-backend-cct" to LibraryOverride(
            website = FIREBASE_ANDROID_SDK_REPO,
        ),
        "com.google.android.datatransport:transport-runtime" to LibraryOverride(
            website = FIREBASE_ANDROID_SDK_REPO,
        ),
    )

    fun apply(rawJson: String): String {
        val root = runCatching { JSONObject(rawJson) }.getOrElse { return rawJson }
        val libraries = root.optJSONArray("libraries") ?: return rawJson
        var mutated = false

        for (index in 0 until libraries.length()) {
            val library = libraries.optJSONObject(index) ?: continue
            val override = libraryOverrides[library.optString("uniqueId")] ?: continue
            if (library.applyOverride(override)) {
                mutated = true
            }
        }

        return if (mutated) root.toString() else rawJson
    }

    private fun JSONObject.applyOverride(override: LibraryOverride): Boolean {
        var mutated = false

        override.name?.let {
            if (optString("name") != it) {
                put("name", it)
                mutated = true
            }
        }
        override.description?.let {
            if (optString("description") != it) {
                put("description", it)
                mutated = true
            }
        }
        override.website?.let {
            if (optString("website") != it) {
                put("website", it)
                mutated = true
            }
        }
        override.artifactVersion?.let {
            if (optString("artifactVersion") != it) {
                put("artifactVersion", it)
                mutated = true
            }
        }
        override.licenses?.let { licenses ->
            val currentLicenses = optJSONArray("licenses")?.toList()
            if (currentLicenses != licenses) {
                put(
                    "licenses",
                    JSONArray().apply {
                        licenses.forEach(::put)
                    },
                )
                mutated = true
            }
        }

        return mutated
    }

    private fun JSONArray.toList(): List<String> {
        return buildList(length()) {
            for (index in 0 until length()) {
                add(optString(index))
            }
        }
    }

    private data class LibraryOverride(
        val name: String? = null,
        val description: String? = null,
        val website: String? = null,
        val artifactVersion: String? = null,
        val licenses: List<String>? = null,
    )
}
