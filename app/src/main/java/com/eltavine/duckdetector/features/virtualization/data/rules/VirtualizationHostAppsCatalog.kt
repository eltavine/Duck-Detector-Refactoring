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

package com.eltavine.duckdetector.features.virtualization.data.rules

data class VirtualizationHostAppTarget(
    val packageName: String,
    val appName: String,
)

object VirtualizationHostAppsCatalog {

    val targets: List<VirtualizationHostAppTarget> = listOf(
        VirtualizationHostAppTarget("com.vmos.pro", "VMOS Pro"),
        VirtualizationHostAppTarget("com.vmos.glb", "VMOS"),
        VirtualizationHostAppTarget("com.vphonegaga.titan", "VPhoneGaGa"),
        VirtualizationHostAppTarget("com.x8zs.sandbox", "X8 Sandbox"),
        VirtualizationHostAppTarget("com.f1player", "F1 VM"),
        VirtualizationHostAppTarget("com.lbe.parallel.intl", "Parallel Space"),
        VirtualizationHostAppTarget("com.parallel.space.lite", "Parallel Space Lite"),
        VirtualizationHostAppTarget("com.excean.gspace", "GSpace"),
        VirtualizationHostAppTarget("io.virtualapp", "VirtualApp"),
        VirtualizationHostAppTarget("io.va.exposed", "VirtualXposed"),
        VirtualizationHostAppTarget("com.bly.dkplat", "Dual Space"),
        VirtualizationHostAppTarget("com.genymotion.superuser", "Genymotion"),
    )

    val targetByPackage: Map<String, VirtualizationHostAppTarget> =
        targets.associateBy { it.packageName }

    val hostTokens: Set<String> = setOf(
        "vmos",
        "vphonegaga",
        "x8zs",
        "f1player",
        "gspace",
        "virtualapp",
        "virtualxposed",
        "genymotion",
        "dkplat",
        "parallelspace",
        "dualspace",
    )

    val specialPaths: Map<String, String> = linkedMapOf(
        "/sdcard/Android/data/com.vmos.pro" to "com.vmos.pro",
        "/sdcard/Android/data/com.vmos.glb" to "com.vmos.glb",
        "/sdcard/Android/data/com.vphonegaga.titan" to "com.vphonegaga.titan",
        "/sdcard/Android/data/com.x8zs.sandbox" to "com.x8zs.sandbox",
        "/sdcard/Android/data/com.f1player" to "com.f1player",
        "/sdcard/Android/data/com.lbe.parallel.intl" to "com.lbe.parallel.intl",
        "/sdcard/Android/data/com.parallel.space.lite" to "com.parallel.space.lite",
        "/sdcard/Android/data/com.excean.gspace" to "com.excean.gspace",
        "/sdcard/Android/data/io.va.exposed" to "io.va.exposed",
    )

    fun findHostPackageInText(text: String): VirtualizationHostAppTarget? {
        val normalized = text.lowercase()
        return targets.firstOrNull { target ->
            normalized.contains(target.packageName.lowercase()) ||
                    normalized.contains(target.appName.lowercase().replace(" ", "")) ||
                    normalized.contains(target.appName.lowercase())
        }
    }

    fun containsHostToken(text: String): Boolean {
        val normalized = text.lowercase()
        val collapsed = normalized.replace(Regex("[^a-z0-9]+"), "")
        return hostTokens.any { token ->
            normalized.contains(token) || collapsed.contains(token)
        }
    }
}
