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

package com.eltavine.duckdetector.features.update.data

import java.time.Instant
import org.json.JSONObject

class UpdateManifestValidationException(message: String) : IllegalArgumentException(message)

internal fun JSONObject.requireObject(name: String): JSONObject {
    return optJSONObject(name)
        ?: throw UpdateManifestValidationException("Missing update manifest object: $name")
}

internal fun JSONObject.requireNonBlankString(name: String): String {
    val rawValue = opt(name)
    if (rawValue !is String) {
        throw UpdateManifestValidationException("Update manifest value must be a string: $name")
    }
    val value = rawValue.trim()
    if (value.isBlank()) {
        throw UpdateManifestValidationException("Missing update manifest string: $name")
    }
    return value
}

internal fun JSONObject.optionalString(name: String): String {
    if (!has(name) || isNull(name)) {
        return ""
    }
    return opt(name) as? String
        ?: throw UpdateManifestValidationException("Update manifest value must be a string: $name")
}

/** Null when the value is absent or JSON null. */
internal fun JSONObject.nullableString(name: String): String? {
    if (!has(name) || isNull(name)) {
        return null
    }
    return requireNonBlankString(name)
}

internal fun JSONObject.requirePositiveInt(name: String): Int {
    val value = requireNonNegativeInt(name)
    if (value == 0) {
        throw UpdateManifestValidationException("Update manifest value must be positive: $name")
    }
    return value
}

internal fun JSONObject.requireNonNegativeInt(name: String): Int {
    val value = when (val rawValue = opt(name)) {
        is Int -> rawValue
        is Long -> rawValue.takeIf { it in 0..Int.MAX_VALUE }?.toInt() ?: -1
        else -> -1
    }
    if (value < 0) {
        throw UpdateManifestValidationException("Update manifest value must be a non-negative integer: $name")
    }
    return value
}

internal fun JSONObject.requirePositiveLong(name: String): Long {
    val value = when (val rawValue = opt(name)) {
        is Int -> rawValue.toLong()
        is Long -> rawValue
        else -> -1L
    }
    if (value <= 0L) {
        throw UpdateManifestValidationException("Update manifest value must be positive: $name")
    }
    return value
}

internal fun JSONObject.requireIsoInstant(name: String): String {
    val value = requireNonBlankString(name)
    runCatching { Instant.parse(value) }
        .getOrElse { throw UpdateManifestValidationException("Update manifest timestamp is invalid: $name") }
    return value
}
