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

package com.eltavine.duckdetector.core.navigation

import androidx.compose.runtime.Composable
import io.github.xiaotong6666.uihelper.navigation3.Navigator
import io.github.xiaotong6666.uihelper.navigation3.logicalBackSwipeDirection
import io.github.xiaotong6666.uihelper.navigation3.rememberNavigator
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import top.yukonga.miuix.kmp.nav.core.NavBackStack
import top.yukonga.miuix.kmp.nav.core.NavDisplay
import top.yukonga.miuix.kmp.nav.core.NavKey
import top.yukonga.miuix.kmp.nav.transition.NavSwipeDirection

/** Tabs are pages *within* Main. Only secondary pages live in this one MIUIX Nav stack. */
@Serializable
sealed interface DuckRoute : NavKey {
    @Serializable @SerialName("main")
    data object Main : DuckRoute
    @Serializable @SerialName("licenses")
    data object Licenses : DuckRoute
}

@Composable
fun rememberDuckRoutes(): Navigator<DuckRoute> = rememberNavigator<DuckRoute>(DuckRoute.Main)

/** Non-inline bridge: the JVM-17 application never inlines MIUIX Nav's JVM-21 DSL. */
@Composable
fun DuckNavHost(
    backStack: NavBackStack,
    onBack: () -> Unit,
    main: @Composable () -> Unit,
    licenses: @Composable () -> Unit,
) {
    val dismissDirection = logicalBackSwipeDirection()
    NavDisplay(backStack = backStack, onBack = onBack) {
        entry<DuckRoute.Main>(swipeDismiss = NavSwipeDirection.None) { main() }
        entry<DuckRoute.Licenses>(swipeDismiss = dismissDirection) { licenses() }
    }
}
