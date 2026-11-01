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

package com.eltavine.duckdetector.features.networkrisk.data.clients

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.eltavine.duckdetector.capability.packageinventory.data.AndroidInstalledPackageInventoryReader
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryReader
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageInventoryResult
import com.eltavine.duckdetector.capability.packageinventory.domain.InstalledPackageVisibility
import com.eltavine.duckdetector.features.networkrisk.domain.*
import java.security.MessageDigest

internal class NetworkClientCollector(
    private val context: Context,
    private val inventoryReader: InstalledPackageInventoryReader = AndroidInstalledPackageInventoryReader(context),
) {
    fun collect(): NetworkClientInventory {
        val result = inventoryReader.read()
        val inventory = (result as? InstalledPackageInventoryResult.Available)?.inventory
        val state = if (inventory == null) ObservationState.UNAVAILABLE else ObservationState.OBSERVED
        return NetworkClientInventory(
            visibility = inventory?.visibility ?: InstalledPackageVisibility.UNKNOWN,
            state = state,
            clients = NetworkClientCatalog.entries.map { definition ->
                if (inventory == null) {
                    NetworkClientEvidence(definition.packageName, definition.name, state)
                } else if (definition.packageName in inventory.packageNames) {
                    readIdentity(definition)
                } else {
                    NetworkClientEvidence(definition.packageName, definition.name, ObservationState.NOT_OBSERVED)
                }
            },
        )
    }

    @Suppress("DEPRECATION")
    private fun readIdentity(definition: NetworkClientDefinition): NetworkClientEvidence {
        val hit = NetworkClientEvidence(definition.packageName, definition.name, ObservationState.OBSERVED)
        return try {
            val flags = PackageManager.GET_SIGNING_CERTIFICATES
            val info = if (Build.VERSION.SDK_INT >= 33) {
                context.packageManager.getPackageInfo(definition.packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else context.packageManager.getPackageInfo(definition.packageName, flags)
            // Only current signers establish a pin match; signing history is not treated as the current key.
            val signers = info.signingInfo?.apkContentsSigners?.mapTo(linkedSetOf()) { signature ->
                MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
            }.orEmpty()
            hit.copy(
                identity = definition.verifyCurrentSigners(signers),
                version = info.longVersionCode.toString(),
                signingState = if (signers.isEmpty()) ObservationState.UNAVAILABLE else ObservationState.OBSERVED,
                signingFailure = if (signers.isEmpty()) ProbeFailure.PLATFORM_FAILURE else null,
            )
        } catch (_: PackageManager.NameNotFoundException) {
            hit.copy(state = ObservationState.INCONCLUSIVE, signingState = ObservationState.INCONCLUSIVE)
        } catch (_: SecurityException) {
            hit.copy(signingState = ObservationState.PERMISSION_LIMITED, signingFailure = ProbeFailure.ACCESS_DENIED)
        } catch (_: RuntimeException) {
            hit.copy(signingFailure = ProbeFailure.PLATFORM_FAILURE)
        }
    }
}
