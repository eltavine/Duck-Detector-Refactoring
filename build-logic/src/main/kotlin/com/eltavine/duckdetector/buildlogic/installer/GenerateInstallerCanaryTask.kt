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

package com.eltavine.duckdetector.buildlogic.installer

import com.android.apksig.ApkSigner
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.*
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault(because = "Produces an application-specific signed diagnostic APK")
abstract class GenerateInstallerCanaryTask @Inject constructor(private val exec: ExecOperations) : DefaultTask() {
    @get:Input abstract val applicationId: Property<String>
    @get:Input abstract val versionCode: Property<Int>
    @get:Input abstract val targetSdk: Property<Int>
    @get:Input abstract val assetPath: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val manifestTemplate: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val aapt2: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val androidJar: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val keyStoreFile: RegularFileProperty
    @get:Input abstract val keyAlias: Property<String>
    @get:Input abstract val keyStoreType: Property<String>
    @get:Internal abstract val storePassword: Property<String>
    @get:Internal abstract val keyPassword: Property<String>
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty

    @TaskAction fun generate() {
        val pkg = applicationId.get()
        require(Regex("[A-Za-z][A-Za-z0-9_]*(?:\\.[A-Za-z][A-Za-z0-9_]*)+").matches(pkg))
        require(versionCode.get() in 1 until Int.MAX_VALUE)
        val manifest = temporaryDir.resolve("AndroidManifest.xml")
        manifest.writeText(manifestTemplate.get().asFile.readText()
            .replace("@APPLICATION_ID@", pkg)
            .replace("@VERSION_CODE@", (versionCode.get() + 1).toString())
            .replace("@TARGET_SDK@", targetSdk.get().toString()))
        val unsigned = temporaryDir.resolve("unsigned.apk")
        exec.exec {
            commandLine(aapt2.get().asFile, "link", "-o", unsigned, "-I", androidJar.get().asFile,
                "--manifest", manifest)
        }.assertNormalExitValue()
        val password = storePassword.get().toCharArray()
        val privatePassword = keyPassword.get().toCharArray()
        try {
            val store = KeyStore.getInstance(keyStoreType.get())
            keyStoreFile.get().asFile.inputStream().use { store.load(it, password) }
            val key = store.getKey(keyAlias.get(), privatePassword) as PrivateKey
            val chain = store.getCertificateChain(keyAlias.get()).map { it as X509Certificate }
            val signer = ApkSigner.SignerConfig.Builder("canary", key, chain).build()
            val output = outputDirectory.get().file(assetPath.get()).asFile
            output.parentFile.mkdirs()
            ApkSigner.Builder(listOf(signer)).setInputApk(unsigned).setOutputApk(output)
                .setMinSdkVersion(33).setV1SigningEnabled(false).setV2SigningEnabled(true)
                .setV3SigningEnabled(true).build().sign()
        } finally {
            password.fill('\u0000')
            privatePassword.fill('\u0000')
        }
    }
}
