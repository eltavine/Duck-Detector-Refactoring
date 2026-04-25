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

package com.eltavine.duckdetector

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.eltavine.duckdetector.core.startup.preload.EarlyMountPreloadStore
import com.eltavine.duckdetector.core.startup.preload.EarlyVirtualizationPreloadStore
import com.eltavine.duckdetector.ui.DuckDetectorApp
import com.eltavine.duckdetector.ui.theme.DuckDetectorTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EarlyMountPreloadStore.capture(intent)
        EarlyVirtualizationPreloadStore.capture(intent)
        enableEdgeToEdge()
        setContent {
            DuckDetectorTheme {
                DuckDetectorApp()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        EarlyMountPreloadStore.capture(intent)
        EarlyVirtualizationPreloadStore.capture(intent)
    }
}
