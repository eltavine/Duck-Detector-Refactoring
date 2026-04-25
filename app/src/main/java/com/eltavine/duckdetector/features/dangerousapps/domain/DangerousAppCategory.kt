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

package com.eltavine.duckdetector.features.dangerousapps.domain

enum class DangerousAppCategory(
    val displayName: String,
) {
    HOOK_FRAMEWORK("Hook framework"),
    APP_HIDE_TOOL("App hiding"),
    ROOT_TOOL("Root tool"),
    LOCATION_SPOOF("Fake location"),
    MOD_TOOL("Cracking / mod"),
    CHAT_HOOK("QQ / WeChat hook"),
    SYSTEM_MODIFICATION("System modification"),
    DEVICE_ID_MODIFICATION("Device ID modification"),
    PRIVACY_BYPASS("Privacy bypass"),
    BACKGROUND_CONTROL("Freezer / background"),
    TERMINAL_DEV("Terminal / dev"),
    MISC("Misc"),
}
