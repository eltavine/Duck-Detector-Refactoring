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

package com.eltavine.duckdetector.features.virtualization.data.probes

import android.os.Build
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignal
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalGroup
import com.eltavine.duckdetector.features.virtualization.domain.VirtualizationSignalSeverity

open class VirtualizationBuildProbe {

    open fun probe(): List<VirtualizationSignal> {
        val fields = listOf(
            "Build.FINGERPRINT" to Build.FINGERPRINT.orEmpty(),
            "Build.PRODUCT" to Build.PRODUCT.orEmpty(),
            "Build.MODEL" to Build.MODEL.orEmpty(),
            "Build.BOARD" to Build.BOARD.orEmpty(),
            "Build.DEVICE" to Build.DEVICE.orEmpty(),
            "Build.BRAND" to Build.BRAND.orEmpty(),
            "Build.MANUFACTURER" to Build.MANUFACTURER.orEmpty(),
            "Build.HOST" to Build.HOST.orEmpty(),
            "Build.TAGS" to Build.TAGS.orEmpty(),
        ).filter { it.second.isNotBlank() }
        return evaluate(fields)
    }

    internal fun evaluate(
        fields: List<Pair<String, String>>,
    ): List<VirtualizationSignal> {
        val strongTokens = listOf(
            "goldfish",
            "ranchu",
            "sdk_gphone",
            "google_sdk",
            "android sdk built for x86",
            "emulator",
            "genymotion",
            "vbox",
            "vbox86p",
        )
        val weakTokens = listOf("generic", "unknown", "test-keys")

        val strongMatches = fields.mapNotNull { (label, value) ->
            strongTokens.firstOrNull { token -> value.contains(token, ignoreCase = true) }
                ?.let { hit ->
                    Triple(label, value, hit)
                }
        }
        val weakMatches = fields.mapNotNull { (label, value) ->
            weakTokens.firstOrNull { token -> value.contains(token, ignoreCase = true) }
                ?.let { hit ->
                    Triple(label, value, hit)
                }
        }

        return buildList {
            strongMatches.forEachIndexed { index, (fieldName, value, token) ->
                add(
                    VirtualizationSignal(
                        id = "virt_build_strong_$index",
                        label = fieldName,
                        value = token,
                        group = VirtualizationSignalGroup.ENVIRONMENT,
                        severity = VirtualizationSignalSeverity.DANGER,
                        detail = "Known emulator build token '$token' matched in $fieldName=$value",
                        detailMonospace = true,
                    ),
                )
            }

            if (strongMatches.isEmpty() && weakMatches.size >= 2) {
                add(
                    VirtualizationSignal(
                        id = "virt_build_weak_cluster",
                        label = "Generic build tokens",
                        value = "${weakMatches.size} hit(s)",
                        group = VirtualizationSignalGroup.ENVIRONMENT,
                        severity = VirtualizationSignalSeverity.WARNING,
                        detail = weakMatches.joinToString(separator = "\n") { (fieldName, value, token) ->
                            "$fieldName matched '$token' in $value"
                        },
                        detailMonospace = true,
                    ),
                )
            }
        }
    }
}
