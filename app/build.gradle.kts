import com.android.build.api.artifact.ArtifactTransformationRequest
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.BuiltArtifact
import com.android.build.api.variant.VariantOutputConfiguration
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

val releaseKeystorePath = providers.environmentVariable("ANDROID_KEYSTORE_PATH").orNull
val releaseStorePassword = providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("ANDROID_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("ANDROID_KEY_PASSWORD").orNull
val buildTimeUtc = ZonedDateTime.now(ZoneOffset.UTC)
    .format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
val buildHash = resolveGitShortHash(rootDir)
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword
).all { !it.isNullOrBlank() }

fun resolveGitShortHash(workingDirectory: File): String {
    return try {
        val process = ProcessBuilder("git", "rev-parse", "--short=12", "HEAD")
            .directory(workingDirectory)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText().trim() }
        if (process.waitFor() == 0) output.ifBlank { "unknown" } else "unknown"
    } catch (_: Exception) {
        "unknown"
    }
}

abstract class RenameApkTask : DefaultTask() {
    @get:InputDirectory
    abstract val inputApkFolder: DirectoryProperty

    @get:OutputDirectory
    abstract val outputApkFolder: DirectoryProperty

    @get:Internal
    abstract val transformationRequest: Property<ArtifactTransformationRequest<RenameApkTask>>

    @TaskAction
    fun renameArtifacts() {
        transformationRequest.get().submit(this) { builtArtifact ->
            val inputFile = File(builtArtifact.outputFile)
            val outputFile = outputApkFolder.file(buildApkFileName(builtArtifact)).get().asFile
            outputFile.parentFile.mkdirs()
            inputFile.copyTo(outputFile, overwrite = true)
            outputFile
        }
    }

    private fun buildApkFileName(builtArtifact: BuiltArtifact): String {
        val apkVersionName = builtArtifact.versionName?.takeIf { it.isNotBlank() } ?: "unknown"
        return when (builtArtifact.outputType) {
            VariantOutputConfiguration.OutputType.ONE_OF_MANY -> {
                val filterSuffix = builtArtifact.filters.joinToString("-") { filter ->
                    "${filter.filterType.name.lowercase()}-${filter.identifier}"
                }
                "Duck Detector-$apkVersionName-$filterSuffix.apk"
            }

            VariantOutputConfiguration.OutputType.SINGLE,
            VariantOutputConfiguration.OutputType.UNIVERSAL -> {
                "Duck Detector-$apkVersionName-Universal.apk"
            }
        }
    }
}

android {
    namespace = "com.eltavine.duckdetector"
    compileSdk = 37
    compileSdkMinor = 0
    ndkVersion = "30.0.14904198 rc1"

    defaultConfig {
        applicationId = "com.eltavine.duckdetector"
        minSdk = 29
        targetSdk = 37
        versionCode = 214
        versionName = "26.3.14-alpha"
        buildConfigField("String", "BUILD_TIME_UTC", "\"$buildTimeUtc\"")
        buildConfigField("String", "BUILD_HASH", "\"$buildHash\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("ciRelease") {
                storeFile = file(requireNotNull(releaseKeystorePath))
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("ciRelease")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "4.1.2"
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    lint {
        baseline = file("lint-baseline.xml")
    }
    buildToolsVersion = "36.1.0"
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val taskName = "rename${
            variant.name.replaceFirstChar { firstChar ->
                if (firstChar.isLowerCase()) {
                    firstChar.titlecase()
                } else {
                    firstChar.toString()
                }
            }
        }Apk"

        val renameTask = tasks.register(taskName, RenameApkTask::class.java)
        val apkTransformationRequest = variant.artifacts
            .use(renameTask)
            .wiredWithDirectories(
                RenameApkTask::inputApkFolder,
                RenameApkTask::outputApkFolder
            )
            .toTransformMany(SingleArtifact.APK)

        renameTask.configure {
            transformationRequest.set(apkTransformationRequest)
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.material)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.compose.icons.simple)
    implementation(libs.aboutlibraries.compose.m3)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.hiddenapibypass)
    implementation(libs.soter.wrapper)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.junit)
    testImplementation(libs.junit)
    testImplementation(libs.json)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    debugImplementation(libs.androidx.ui.tooling)
}
