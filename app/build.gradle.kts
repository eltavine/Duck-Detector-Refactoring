plugins {
    id("duckdetector.android.application")
    id("duckdetector.android.apk-artifacts")
}

android {
    namespace = "com.eltavine.duckdetector"

    defaultConfig {
        applicationId = "com.eltavine.duckdetector"
        versionCode = 215
        versionName = "26.4.1"
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.bundles.app.runtime)
    implementation(libs.bundles.app.compose)
    implementation(libs.aboutlibraries.compose.m3) {
        exclude(group = "com.github.skydoves", module = "compose-stability-runtime")
    }
    implementation(libs.bundles.app.security)
    testImplementation(libs.bundles.test.unit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.bundles.test.android)
    debugImplementation(libs.androidx.ui.tooling)
}
