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

/** Platform-neutral projection of the ApplicationInfo fields used by package-based probes. */
data class InstalledApplicationRecord(
    val packageName: String,
    val label: String,
    val metadataKeys: Set<String>,
)

data class InstalledApplicationQueryOptions(
    val includeMetadata: Boolean = false,
    val resolveLabelsForMetadataKeys: Set<String> = emptySet(),
)

enum class PackageInventoryFailureKind {
    PLATFORM_QUERY_FAILED,
    VISIBILITY_ENVIRONMENT_FAILED,
}

data class PackageInventoryFailure(
    val kind: PackageInventoryFailureKind,
    val detail: String,
)

sealed interface InstalledApplicationsQueryResult {
    data class Available(
        val applications: List<InstalledApplicationRecord>,
    ) : InstalledApplicationsQueryResult

    data class Unavailable(
        val failure: PackageInventoryFailure,
    ) : InstalledApplicationsQueryResult
}

fun interface InstalledApplicationsSource {
    fun query(): InstalledApplicationsQueryResult
}

fun interface PackageVisibilityEnvironmentProvider {
    fun read(): PackageVisibilityEnvironment
}

data class InstalledPackageInventory(
    val applications: List<InstalledApplicationRecord>,
    val visibility: InstalledPackageVisibility,
    val suspiciouslyLowInventory: Boolean,
) {
    val packageNames: Set<String> = applications.mapTo(linkedSetOf()) { it.packageName }
    val visiblePackageCount: Int
        get() = packageNames.size
}

sealed interface InstalledPackageInventoryResult {
    data class Available(
        val inventory: InstalledPackageInventory,
    ) : InstalledPackageInventoryResult

    data class Unavailable(
        val failure: PackageInventoryFailure,
    ) : InstalledPackageInventoryResult
}

fun interface InstalledPackageInventoryReader {
    fun read(): InstalledPackageInventoryResult
}

class DefaultInstalledPackageInventoryReader(
    private val callerPackageName: String,
    private val applicationsSource: InstalledApplicationsSource,
    private val environmentProvider: PackageVisibilityEnvironmentProvider,
) : InstalledPackageInventoryReader {

    override fun read(): InstalledPackageInventoryResult {
        return when (val query = applicationsSource.query()) {
            is InstalledApplicationsQueryResult.Unavailable -> {
                InstalledPackageInventoryResult.Unavailable(query.failure)
            }

            is InstalledApplicationsQueryResult.Available -> {
                val packageNames = query.applications.mapTo(linkedSetOf()) { it.packageName }
                val environment = try {
                    environmentProvider.read()
                } catch (exception: Exception) {
                    return InstalledPackageInventoryResult.Unavailable(
                        PackageInventoryFailure(
                            kind = PackageInventoryFailureKind.VISIBILITY_ENVIRONMENT_FAILED,
                            detail = exception.toInventoryFailureDetail(),
                        ),
                    )
                }
                val visibility = InstalledPackageVisibilityPolicy.evaluate(
                    environment = environment,
                    callerPackageObserved = callerPackageName in packageNames,
                )
                InstalledPackageInventoryResult.Available(
                    InstalledPackageInventory(
                        applications = query.applications,
                        visibility = visibility,
                        suspiciouslyLowInventory =
                            InstalledPackageInventoryAnomalyPolicy.isSuspiciouslyLow(
                                visibility = visibility,
                                installedPackageCount = packageNames.size,
                                sdkInt = environment.deviceSdk,
                            ),
                    ),
                )
            }
        }
    }

    private fun Exception.toInventoryFailureDetail(): String {
        return buildString {
            append(this@toInventoryFailureDetail::class.java.simpleName.ifBlank {
                "Package visibility environment error"
            })
            message?.takeIf { it.isNotBlank() }?.let { errorMessage ->
                append(": ")
                append(errorMessage)
            }
        }
    }
}
