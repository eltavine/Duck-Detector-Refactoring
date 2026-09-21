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

package com.eltavine.duckdetector.core.packagevisibility

import android.content.Context
import android.os.Build

/** The visibility guarantee provided by PackageManager, not a guess based on list size. */
enum class InstalledPackageVisibility {
    UNKNOWN,
    FULL,
    RESTRICTED,
}

data class PackageVisibilityEnvironment(
    val deviceSdk: Int,
    val targetSdk: Int,
    val queryAllPackagesRequested: Boolean,
)

/**
 * Pure policy for Android's package-visibility compatibility contract.
 *
 * Android 11 enables FILTER_APPLICATION_QUERY for callers targeting API 30 or newer. A caller
 * that requests the normal QUERY_ALL_PACKAGES permission is exempt. Counts deliberately do not
 * participate: automatically visible packages can make a filtered result arbitrarily large.
 */
object InstalledPackageVisibilityPolicy {

    fun evaluate(
        environment: PackageVisibilityEnvironment,
        callerPackageObserved: Boolean,
    ): InstalledPackageVisibility {
        // A successful PackageManager inventory must include the caller. Missing it means the
        // observed response no longer satisfies the platform baseline, so absence claims are not
        // defensible even if the manifest requests broad visibility.
        if (!callerPackageObserved) {
            return InstalledPackageVisibility.UNKNOWN
        }
        if (environment.deviceSdk < Build.VERSION_CODES.R ||
            environment.targetSdk < Build.VERSION_CODES.R
        ) {
            return InstalledPackageVisibility.FULL
        }
        return if (environment.queryAllPackagesRequested) {
            InstalledPackageVisibility.FULL
        } else {
            InstalledPackageVisibility.RESTRICTED
        }
    }
}

object InstalledPackageInventoryAnomalyPolicy {

    const val SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT = 60

    fun isSuspiciouslyLow(
        visibility: InstalledPackageVisibility,
        installedPackageCount: Int,
        sdkInt: Int,
    ): Boolean {
        return sdkInt >= Build.VERSION_CODES.R &&
                visibility == InstalledPackageVisibility.FULL &&
                installedPackageCount < SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT
    }
}

/**
 * Compatibility facade for callers that have not moved to [InstalledPackageInventoryReader].
 *
 * New code should consume the inventory result as one value. Keeping the old entry points avoids
 * a source-level breaking change while internal callers migrate away from the former two-step
 * `getInstalledPackages()` + `detect(count)` protocol, which could not distinguish query failure
 * from a successful empty response.
 */
object InstalledPackageVisibilityChecker {

    const val SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT =
        InstalledPackageInventoryAnomalyPolicy.SUSPICIOUSLY_LOW_VISIBLE_PACKAGE_COUNT

    fun inspect(context: Context): InstalledPackageInventoryResult {
        return AndroidInstalledPackageInventoryReader(context.applicationContext).read()
    }

    fun hasSuspiciouslyLowInventory(
        visibility: InstalledPackageVisibility,
        installedPackageCount: Int,
        sdkInt: Int = Build.VERSION.SDK_INT,
    ): Boolean {
        return InstalledPackageInventoryAnomalyPolicy.isSuspiciouslyLow(
            visibility = visibility,
            installedPackageCount = installedPackageCount,
            sdkInt = sdkInt,
        )
    }

    @Deprecated(
        message = "Read InstalledPackageInventoryResult so query failure remains explicit.",
        replaceWith = ReplaceWith("InstalledPackageVisibilityChecker.inspect(context)"),
    )
    fun getInstalledPackages(context: Context): Set<String> {
        return when (val result = inspect(context)) {
            is InstalledPackageInventoryResult.Available -> result.inventory.packageNames
            is InstalledPackageInventoryResult.Unavailable -> emptySet()
        }
    }

    @Deprecated(
        message = "Visibility cannot be derived safely from a count; inspect the inventory.",
        replaceWith = ReplaceWith("InstalledPackageVisibilityChecker.inspect(context)"),
    )
    fun detect(
        context: Context,
        installedPackageCount: Int,
    ): InstalledPackageVisibility {
        return resolveVisibility(
            inventoryHasCaller = installedPackageCount > 0,
            environment = AndroidPackageVisibilityEnvironmentProvider(context).read(),
        )
    }

    internal fun resolveVisibility(
        inventoryHasCaller: Boolean,
        environment: PackageVisibilityEnvironment,
    ): InstalledPackageVisibility {
        return InstalledPackageVisibilityPolicy.evaluate(
            environment = environment,
            callerPackageObserved = inventoryHasCaller,
        )
    }
}
