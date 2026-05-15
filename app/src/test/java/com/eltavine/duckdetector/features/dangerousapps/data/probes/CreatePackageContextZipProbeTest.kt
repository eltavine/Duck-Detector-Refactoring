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

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CreatePackageContextZipProbeTest {

    @Test
    fun `application info paths are normalized and deduplicated`() {
        val paths = CreatePackageContextZipProbe.collectApkPaths(
            sourceDir = " /data/app/com.termux/base.apk ",
            publicSourceDir = "/data/app/com.termux/base.apk",
            splitSourceDirs = listOf(
                "\\data\\app\\com.termux\\split_config.arm64_v8a.apk",
                "/data/app/com.termux/not_apk.dm",
            ),
            splitPublicSourceDirs = listOf(
                "/data/app/com.termux/split_config.arm64_v8a.apk",
                "",
            ),
        )

        assertEquals(
            listOf(
                "/data/app/com.termux/base.apk",
                "/data/app/com.termux/split_config.arm64_v8a.apk",
            ),
            paths,
        )
    }

    @Test
    fun `only target packages with readable apk zips are detected`() {
        val result = CreatePackageContextZipProbe.evaluate(
            packageApkPathsByPackage = mapOf(
                "com.termux" to listOf("/data/app/com.termux/base.apk"),
                "com.omarea.vtools" to listOf("/data/app/com.omarea.vtools/base.apk"),
                "org.lsposed.manager" to null,
            ),
            targetPackages = setOf("com.termux", "com.omarea.vtools", "org.lsposed.manager"),
            zipInspector = { path -> path.contains("com.termux") },
        )

        assertTrue(result.available)
        assertEquals(setOf("com.termux"), result.detectedPackages)
        assertEquals(
            listOf("/data/app/com.termux/base.apk"),
            result.matchedPathsByPackage.getValue("com.termux"),
        )
    }

    @Test
    fun `zip inspector failure skips only that apk path`() {
        val result = CreatePackageContextZipProbe.evaluate(
            packageApkPathsByPackage = mapOf(
                "com.termux" to listOf(
                    "/data/app/com.termux/broken.apk",
                    "/data/app/com.termux/base.apk",
                ),
            ),
            targetPackages = setOf("com.termux"),
            zipInspector = { path ->
                if (path.contains("broken")) {
                    throw IllegalStateException("failed to open zip")
                }
                true
            },
        )

        assertTrue(result.available)
        assertEquals(setOf("com.termux"), result.detectedPackages)
        assertEquals(
            listOf("/data/app/com.termux/base.apk"),
            result.matchedPathsByPackage.getValue("com.termux"),
        )
    }

    @Test
    fun `package context identity must match requested package`() {
        assertTrue(
            CreatePackageContextZipProbe.matchesPackageName(
                expectedPackageName = "com.termux",
                contextPackageName = "com.termux",
                applicationInfoPackageName = "com.termux",
            ),
        )
        assertFalse(
            CreatePackageContextZipProbe.matchesPackageName(
                expectedPackageName = "com.termux",
                contextPackageName = "com.fake.wrapper",
                applicationInfoPackageName = "com.termux",
            ),
        )
        assertFalse(
            CreatePackageContextZipProbe.matchesPackageName(
                expectedPackageName = "com.termux",
                contextPackageName = "com.termux",
                applicationInfoPackageName = null,
            ),
        )
    }

    @Test
    fun `zip inspector requires android manifest entry`() {
        val apk = createZipFile(
            name = "with-manifest.apk",
            entries = listOf("AndroidManifest.xml", "classes.dex"),
        )
        val plainZip = createZipFile(
            name = "without-manifest.apk",
            entries = listOf("classes.dex"),
        )
        val textFile = File.createTempFile("not-an-apk", ".apk").apply {
            writeText("not a zip")
            deleteOnExit()
        }

        assertTrue(CreatePackageContextZipProbe.isReadableApkZip(apk.absolutePath))
        assertFalse(CreatePackageContextZipProbe.isReadableApkZip(plainZip.absolutePath))
        assertFalse(CreatePackageContextZipProbe.isReadableApkZip(textFile.absolutePath))
    }

    private fun createZipFile(
        name: String,
        entries: List<String>,
    ): File {
        val file = File.createTempFile(name.substringBefore('.'), ".apk").apply {
            deleteOnExit()
        }
        ZipOutputStream(file.outputStream()).use { zip ->
            entries.forEach { entryName ->
                zip.putNextEntry(ZipEntry(entryName))
                zip.write(byteArrayOf(1))
                zip.closeEntry()
            }
        }
        return file
    }
}
