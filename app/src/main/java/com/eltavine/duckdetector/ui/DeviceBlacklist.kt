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

package com.eltavine.duckdetector.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Process
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.eltavine.duckdetector.core.ui.components.WrapSafeText
import kotlinx.coroutines.delay
import kotlin.system.exitProcess

internal data class DeviceBlacklistMatch(
    val manufacturer: String,
    val message: String,
)

internal object DeviceBlacklist {

    fun matchCurrentDevice(): DeviceBlacklistMatch? {
        return match(
            manufacturer = Build.MANUFACTURER,
            brand = Build.BRAND,
        )
    }

    fun match(
        manufacturer: String?,
        brand: String?,
    ): DeviceBlacklistMatch? {
        val normalizedManufacturer = manufacturer.orEmpty().trim().lowercase()
        val normalizedBrand = brand.orEmpty().trim().lowercase()
        val isHuawei = normalizedManufacturer == "huawei" || normalizedBrand == "huawei"
        if (!isHuawei) {
            return null
        }
        return DeviceBlacklistMatch(
            manufacturer = manufacturer?.takeIf { it.isNotBlank() } ?: "HUAWEI",
            message = "HUAWEI devices are not supported.",
        )
    }
}

@Composable
internal fun BlockedDeviceScreen(
    match: DeviceBlacklistMatch,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val activity = context.findActivity()

    LaunchedEffect(match.message) {
        Toast.makeText(context, match.message, Toast.LENGTH_LONG).show()
        delay(1200)
        activity?.finishAffinity()
        Process.killProcess(Process.myPid())
        exitProcess(0)
    }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            WrapSafeText(
                text = "Unsupported device",
                style = MaterialTheme.typography.displaySmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = "${match.manufacturer} devices are blocked by the current blacklist.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
            WrapSafeText(
                text = "Duck Detector will close now.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private tailrec fun Context.findActivity(): Activity? {
    return when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.findActivity()
        else -> null
    }
}
