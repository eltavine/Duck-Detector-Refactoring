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

package com.eltavine.duckdetector.features.dangerousapps.data.probes

import android.content.Context
import android.content.pm.ApplicationInfo
import java.io.File
import java.util.zip.ZipFile

data class CreatePackageContextZipProbeResult(
    val matchedPathsByPackage: Map<String, List<String>>,
    val available: Boolean,
) {
    val detectedPackages: Set<String>
        get() = matchedPathsByPackage.keys
}

class CreatePackageContextZipProbe(
    private val context: Context,
) {

    fun run(
        targetPackages: Set<String>,
    ): CreatePackageContextZipProbeResult {
        return evaluate(
            packageApkPathsByPackage = targetPackages.associateWith(::resolvePackageApkPaths),
            targetPackages = targetPackages,
        )
    }

    private fun resolvePackageApkPaths(packageName: String): List<String>? {
        return try {
            // Keep this metadata-only: never pass CONTEXT_INCLUDE_CODE for untrusted target packages.
            val packageContext = context.createPackageContext(packageName, 0)
            val applicationInfo = packageContext.applicationInfo
            if (!matchesPackageName(packageName, packageContext.packageName, applicationInfo.packageName)) {
                null
            } else {
                collectApplicationInfoApkPaths(applicationInfo)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun collectApplicationInfoApkPaths(
        applicationInfo: ApplicationInfo,
    ): List<String> {
        return collectApkPaths(
            sourceDir = applicationInfo.sourceDir,
            publicSourceDir = applicationInfo.publicSourceDir,
            splitSourceDirs = applicationInfo.splitSourceDirs?.toList(),
            splitPublicSourceDirs = applicationInfo.splitPublicSourceDirs?.toList(),
        )
    }

    internal companion object {

        fun evaluate(
            packageApkPathsByPackage: Map<String, List<String>?>,
            targetPackages: Set<String>,
            zipInspector: (String) -> Boolean = ::isReadableApkZip,
        ): CreatePackageContextZipProbeResult {
            val matchedPaths = linkedMapOf<String, List<String>>()

            targetPackages.forEach { packageName ->
                val readablePaths = packageApkPathsByPackage[packageName]
                    .orEmpty()
                    .asSequence()
                    .map(::normalizeApkPath)
                    .filter { it.isNotBlank() }
                    .filter(::looksLikeApkPath)
                    .distinct()
                    .filter { path ->
                        try {
                            zipInspector(path)
                        } catch (_: Exception) {
                            false
                        }
                    }
                    .toList()
                if (readablePaths.isNotEmpty()) {
                    matchedPaths[packageName] = readablePaths
                }
            }

            return CreatePackageContextZipProbeResult(
                matchedPathsByPackage = matchedPaths,
                available = true,
            )
        }

        fun collectApkPaths(
            sourceDir: String?,
            publicSourceDir: String?,
            splitSourceDirs: List<String>?,
            splitPublicSourceDirs: List<String>?,
        ): List<String> {
            return buildList {
                add(sourceDir)
                add(publicSourceDir)
                addAll(splitSourceDirs.orEmpty())
                addAll(splitPublicSourceDirs.orEmpty())
            }
                .asSequence()
                .map(::normalizeApkPath)
                .filter { it.isNotBlank() }
                .filter(::looksLikeApkPath)
                .distinct()
                .toList()
        }

        fun isReadableApkZip(path: String): Boolean {
            return try {
                ZipFile(File(path), ZipFile.OPEN_READ).use { zip ->
                    zip.size() > 0 && zip.getEntry(APK_MANIFEST_ENTRY) != null
                }
            } catch (_: Exception) {
                false
            }
        }

        fun matchesPackageName(
            expectedPackageName: String,
            contextPackageName: String?,
            applicationInfoPackageName: String?,
        ): Boolean {
            return expectedPackageName.isNotBlank() &&
                    expectedPackageName == contextPackageName &&
                    expectedPackageName == applicationInfoPackageName
        }

        private fun normalizeApkPath(path: String?): String {
            return path
                ?.trim()
                ?.replace('\\', '/')
                .orEmpty()
        }

        private fun looksLikeApkPath(path: String): Boolean {
            return path.lowercase().endsWith(".apk")
        }

        private const val APK_MANIFEST_ENTRY = "AndroidManifest.xml"
    }
}
