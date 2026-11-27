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

package com.eltavine.duckdetector.features.tee.data.verification.strongbox

import android.os.Build
import com.eltavine.duckdetector.features.tee.data.verification.keystore.Keystore2PrivateBinderClient
import com.eltavine.duckdetector.features.tee.data.verification.keystore.describeKeystoreThrowable
import com.eltavine.duckdetector.features.tee.data.verification.keystore.keystoreServiceSpecificErrorCode
import java.lang.reflect.InvocationTargetException

internal fun inspectStrongBoxBinder(
    sdkInt: Int,
    manifestPaths: List<String>,
    advertised: Boolean?,
    readMergedManifest: () -> Boolean?,
    querySecurityLevel: () -> Any? = {
        val client = Keystore2PrivateBinderClient()
        val service = checkNotNull(client.getKeystoreService()) { "Keystore2 service interface unavailable" }
        client.resolveSecurityLevelOrThrow(service, Keystore2PrivateBinderClient.SECURITY_LEVEL_STRONGBOX)
    },
): StrongBoxBinderObservation? {
    if (sdkInt < Build.VERSION_CODES.TIRAMISU) return null

    // Android 14 libvintf can omit vendor APEX fragments when the app cannot read the APEX list.
    val checkMergedManifest = sdkInt == Build.VERSION_CODES.TIRAMISU
    val mergedDeclaration = if (checkMergedManifest) readMergedManifest() else null
    val confirmedDeclaration = advertised == true || mergedDeclaration == true
    val shouldQuery = !checkMergedManifest || confirmedDeclaration ||
        (mergedDeclaration != false && manifestPaths.isNotEmpty())
    if (!shouldQuery && advertised == false && mergedDeclaration == false) return null

    val declarations = buildList {
        add(
            when (advertised) {
                true -> "PackageManager declares StrongBox"
                false -> "PackageManager does not declare StrongBox"
                null -> "PackageManager declaration could not be read"
            },
        )
        if (checkMergedManifest) {
            add(
                when (mergedDeclaration) {
                    true -> "Merged device VINTF manifest declares StrongBox"
                    false -> "Merged device VINTF manifest does not declare StrongBox"
                    null -> "The merged device VINTF manifest could not be read or parsed."
                },
            )
        }
        if (manifestPaths.isNotEmpty()) {
            val effectiveState = when (mergedDeclaration) {
                true -> ""
                false -> " (instance absent from the merged device manifest)"
                null -> " (effective declaration unverified)"
            }
            add("VINTF XML: ${manifestPaths.joinToString()}$effectiveState")
        } else if (!checkMergedManifest) {
            add("No StrongBox declaration was found in the readable VINTF files.")
        }
    }
    if (!shouldQuery) {
        return StrongBoxBinderObservation(
            queryFailed = false,
            confirmedDeclaration = false,
            summary = DECLARATION_UNVERIFIED,
            detail = (declarations + "The Keystore2 query was skipped.").joinToString("\n"),
        )
    }

    val query = runCatching(querySecurityLevel)
    val failure = query.exceptionOrNull()
    val invocationFailure = (failure as? InvocationTargetException)?.targetException
    val hardwareUnavailable = invocationFailure?.let(::keystoreServiceSpecificErrorCode) == HARDWARE_TYPE_UNAVAILABLE
    if (hardwareUnavailable && advertised == false && !confirmedDeclaration && manifestPaths.isEmpty()) return null

    val interfaceAvailable = query.getOrNull() != null
    val missingSystemFeature = advertised == false && (mergedDeclaration == true || interfaceAvailable)
    val queryIssue = when {
        hardwareUnavailable -> "Keystore2 reports it unavailable."
        invocationFailure != null -> "The Keystore2 query failed."
        else -> null
    }
    val summary = when {
        missingSystemFeature && mergedDeclaration == true ->
            listOfNotNull("VINTF declares StrongBox. Android does not advertise it.", queryIssue).joinToString(" ")
        missingSystemFeature -> "Keystore2 exposes a StrongBox interface. Android does not advertise it."
        !confirmedDeclaration && advertised == false && manifestPaths.isNotEmpty() ->
            "VINTF XML lists StrongBox. Android does not advertise it."
        interfaceAvailable -> "Keystore2 exposes a StrongBox interface"
        !confirmedDeclaration -> DECLARATION_UNVERIFIED
        queryIssue != null -> "The device declares StrongBox. $queryIssue"
        else -> "Could not check StrongBox availability"
    }
    val queryDetail = when {
        invocationFailure != null -> "getSecurityLevel(STRONGBOX) threw ${describeKeystoreThrowable(invocationFailure)}"
        failure != null -> "Could not call getSecurityLevel(STRONGBOX) (${describeKeystoreThrowable(failure)})"
        interfaceAvailable -> "getSecurityLevel(STRONGBOX) returned an interface"
        else -> "getSecurityLevel(STRONGBOX) returned no interface"
    }
    return StrongBoxBinderObservation(
        queryFailed = invocationFailure != null,
        confirmedDeclaration = confirmedDeclaration,
        summary = summary,
        detail = (declarations + queryDetail).joinToString("\n"),
        missingSystemFeature = missingSystemFeature,
    )
}

private const val HARDWARE_TYPE_UNAVAILABLE = -68
private const val DECLARATION_UNVERIFIED = "StrongBox declaration could not be verified"
