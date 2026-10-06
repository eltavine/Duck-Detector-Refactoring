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

package com.eltavine.duckdetector.capability.systemproperties.domain

public data class AdbRootPropertyAssessment(
    val value: String,
    val source: SystemPropertySource,
    val severity: SystemPropertySeverity,
    val detail: String,
) {
    public val rootRequested: Boolean
        get() = value == "1"
}

/**
 * Shared semantic assessment for service.adb.root.
 *
 * Keeping this in the system-properties capability makes every detector consume the same
 * multi-source preferred value and root-request semantics instead of reimplementing them.
 */
public fun assessAdbRootProperty(
    adbRoot: MultiSourcePropertyRead,
    debuggable: MultiSourcePropertyRead? = null,
): AdbRootPropertyAssessment? {
    val value = adbRoot.preferredValue.trim()
    if (value.isEmpty()) {
        return null
    }
    val debuggableValue = debuggable?.preferredValue?.trim().orEmpty()
    val severity = when (value) {
        "1" -> SystemPropertySeverity.DANGER
        "0" -> SystemPropertySeverity.SAFE
        else -> SystemPropertySeverity.NEUTRAL
    }
    val detail = when {
        value == "1" && debuggableValue == "1" ->
            "service.adb.root=1 is the explicit adb root request, and ro.debuggable=1 allows AOSP adbd to keep root privileges."

        value == "1" ->
            "service.adb.root=1 records an explicit adb root request/state. ro.debuggable=${debuggableValue.ifEmpty { "unavailable" }} means this property alone does not prove the daemon actually kept UID 0."

        value == "0" ->
            "ADB root property is disabled."

        else ->
            "ADB root property is present but does not match the usual production values."
    }
    return AdbRootPropertyAssessment(
        value = value,
        source = adbRoot.preferredSource,
        severity = severity,
        detail = detail,
    )
}
