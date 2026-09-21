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
import android.content.pm.PackageManager
import android.os.Build

private const val QUERY_ALL_PACKAGES_PERMISSION = "android.permission.QUERY_ALL_PACKAGES"

/** Android adapter; all PackageManager API-level branching is owned here. */
class AndroidInstalledApplicationsSource(
    context: Context,
    private val options: InstalledApplicationQueryOptions = InstalledApplicationQueryOptions(),
) : InstalledApplicationsSource {

    private val appContext = context.applicationContext

    @Suppress("DEPRECATION")
    override fun query(): InstalledApplicationsQueryResult {
        return try {
            val packageManager = appContext.packageManager
            val flags = if (options.includeMetadata) PackageManager.GET_META_DATA else 0
            val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(flags.toLong()),
                )
            } else {
                packageManager.getInstalledApplications(flags)
            }
            InstalledApplicationsQueryResult.Available(
                applications.map { application ->
                    val metadataKeys = if (options.includeMetadata) {
                        application.metaData?.keySet()?.toSet().orEmpty()
                    } else {
                        emptySet()
                    }
                    val shouldResolveLabel = metadataKeys.any {
                        it in options.resolveLabelsForMetadataKeys
                    }
                    InstalledApplicationRecord(
                        packageName = application.packageName,
                        label = if (shouldResolveLabel) {
                            try {
                                packageManager.getApplicationLabel(application).toString()
                            } catch (_: Exception) {
                                application.packageName
                            }
                        } else {
                            application.packageName
                        },
                        metadataKeys = metadataKeys,
                    )
                },
            )
        } catch (exception: Exception) {
            InstalledApplicationsQueryResult.Unavailable(
                PackageInventoryFailure(
                    kind = PackageInventoryFailureKind.PLATFORM_QUERY_FAILED,
                    detail = buildString {
                        append(exception::class.java.simpleName.ifBlank { "PackageManager error" })
                        exception.message?.takeIf { it.isNotBlank() }?.let { message ->
                            append(": ")
                            append(message)
                        }
                    },
                ),
            )
        }
    }
}

class AndroidPackageVisibilityEnvironmentProvider(
    context: Context,
) : PackageVisibilityEnvironmentProvider {

    private val appContext = context.applicationContext

    @Suppress("DEPRECATION")
    override fun read(): PackageVisibilityEnvironment {
        val deviceSdk = Build.VERSION.SDK_INT
        val targetSdk = appContext.applicationInfo.targetSdkVersion
        if (deviceSdk < Build.VERSION_CODES.R || targetSdk < Build.VERSION_CODES.R) {
            return PackageVisibilityEnvironment(
                deviceSdk = deviceSdk,
                targetSdk = targetSdk,
                queryAllPackagesRequested = false,
            )
        }
        val flags = PackageManager.GET_PERMISSIONS
        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            appContext.packageManager.getPackageInfo(
                appContext.packageName,
                PackageManager.PackageInfoFlags.of(flags.toLong()),
            )
        } else {
            appContext.packageManager.getPackageInfo(appContext.packageName, flags)
        }
        return PackageVisibilityEnvironment(
            deviceSdk = deviceSdk,
            targetSdk = targetSdk,
            // AppsFilterUtils reads the parsed manifest's requested permissions directly. Do the
            // same rather than substituting runtime-permission state for the platform rule.
            queryAllPackagesRequested = packageInfo.requestedPermissions
                .orEmpty()
                .contains(QUERY_ALL_PACKAGES_PERMISSION),
        )
    }
}

class AndroidInstalledPackageInventoryReader(
    context: Context,
    queryOptions: InstalledApplicationQueryOptions = InstalledApplicationQueryOptions(),
    applicationsSource: InstalledApplicationsSource =
        AndroidInstalledApplicationsSource(context, queryOptions),
    environmentProvider: PackageVisibilityEnvironmentProvider =
        AndroidPackageVisibilityEnvironmentProvider(context),
) : InstalledPackageInventoryReader {

    private val delegate = DefaultInstalledPackageInventoryReader(
        callerPackageName = context.packageName,
        applicationsSource = applicationsSource,
        environmentProvider = environmentProvider,
    )

    override fun read(): InstalledPackageInventoryResult = delegate.read()
}
