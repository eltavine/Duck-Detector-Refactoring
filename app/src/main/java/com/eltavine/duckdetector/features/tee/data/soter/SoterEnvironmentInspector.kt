package com.eltavine.duckdetector.features.tee.data.soter

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.util.Locale

internal data class SoterEnvironmentSnapshot(
    val supportExpected: Boolean = false,
    val simplifiedChineseLocale: Boolean = false,
    val servicePackageVisible: Boolean = true,
) {
    val abnormalEnvironment: Boolean
        get() = supportExpected && simplifiedChineseLocale && !servicePackageVisible
}

internal fun interface SoterEnvironmentInspector {
    fun inspect(): SoterEnvironmentSnapshot
}

internal class AndroidSoterEnvironmentInspector(
    context: Context,
    private val supportCatalog: SoterSupportCatalog = SoterSupportCatalog(),
) : SoterEnvironmentInspector {

    private val appContext = context.applicationContext

    override fun inspect(): SoterEnvironmentSnapshot {
        val locale = appContext.resources.configuration.locales[0] ?: Locale.getDefault()
        return SoterEnvironmentSnapshot(
            supportExpected = supportCatalog.expectsSupport(),
            simplifiedChineseLocale = isSimplifiedChinese(locale),
            servicePackageVisible = isPackageVisible(SOTER_SERVICE_PACKAGE),
        )
    }

    @Suppress("DEPRECATION")
    private fun isPackageVisible(packageName: String): Boolean {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appContext.packageManager.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(0),
                )
            } else {
                appContext.packageManager.getPackageInfo(packageName, 0)
            }
        }.isSuccess
    }

    private fun isSimplifiedChinese(locale: Locale): Boolean {
        if (!locale.language.equals("zh", ignoreCase = true)) {
            return false
        }
        val script = locale.script
        if (script.equals("Hans", ignoreCase = true)) {
            return true
        }
        return script.isBlank() && locale.country.uppercase(Locale.US) in SIMPLIFIED_CHINESE_REGIONS
    }

    private companion object {
        private const val SOTER_SERVICE_PACKAGE = "com.tencent.soter.soterserver"
        private val SIMPLIFIED_CHINESE_REGIONS = setOf("CN", "SG")
    }
}
