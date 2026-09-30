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

package com.eltavine.duckdetector

import android.content.Intent
import android.os.Bundle
import android.view.ViewGroup
import android.webkit.WebView
import android.widget.FrameLayout
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.ComposeView
import com.eltavine.duckdetector.core.designsystem.theme.DuckDetectorTheme
import com.eltavine.duckdetector.core.ui.AppBuildInfo
import com.eltavine.duckdetector.core.ui.LocalAppBuildInfo
import com.eltavine.duckdetector.sdk.DuckDetector
import com.eltavine.duckdetector.ui.DuckDetectorApp
import com.eltavine.duckdetector.ui.StartupBootstrapLoadingScreen
import com.eltavine.duckdetector.ui.appearance.UiAppearanceStore
import io.github.xiaotong6666.uihelper.mode.UiMode
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private var procMountSampler: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DuckDetector.captureLaunchEvidence(intent)
        enableEdgeToEdge()
        // Attached before Compose starts, as the SDK asks.
        procMountSampler = DuckDetector.createProcMountSampler(this)
        val root = FrameLayout(this)
        procMountSampler?.let { sampler ->
            root.addView(sampler, FrameLayout.LayoutParams(1, 1))
        }
        val composeView = ComposeView(this)
        root.addView(
            composeView,
            FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            ),
        )
        setContentView(root)
        val appearanceStore = UiAppearanceStore.getInstance(applicationContext)
        composeView.setContent {
            // Resolve the saved mode before rendering the app, otherwise a saved Material choice
            // briefly flashes MIUIX on every cold start.
            val uiMode by produceState<UiMode?>(initialValue = null, key1 = appearanceStore) {
                appearanceStore.mode.collect { value = it }
            }
            val scope = rememberCoroutineScope()
            CompositionLocalProvider(LocalAppBuildInfo provides appBuildInfo) {
                DuckDetectorTheme(uiMode = uiMode ?: UiMode.Miuix) {
                    if (uiMode == null) {
                        StartupBootstrapLoadingScreen()
                    } else {
                        DuckDetectorApp(onUiModeChange = { selected ->
                            scope.launch { appearanceStore.setMode(selected) }
                        })
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        DuckDetector.captureLaunchEvidence(intent)
    }

    override fun onDestroy() {
        val sampler = procMountSampler
        (sampler?.parent as? ViewGroup)?.removeView(sampler)
        sampler?.destroy()
        procMountSampler = null
        super.onDestroy()
    }

    private val appBuildInfo = AppBuildInfo(
        versionName = BuildConfig.VERSION_NAME,
        versionCode = BuildConfig.VERSION_CODE,
        buildHash = BuildConfig.BUILD_HASH,
        buildTimeUtc = BuildConfig.BUILD_TIME_UTC,
        isAlphaVersion = BuildConfig.isAlphaVersion,
    )
}
