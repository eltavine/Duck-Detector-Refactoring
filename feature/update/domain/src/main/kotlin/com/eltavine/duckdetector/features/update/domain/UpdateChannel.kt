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

package com.eltavine.duckdetector.features.update.domain

/**
 * Stable follows the tagged releases and Nightly every change to main. [id] is how update.json and
 * the build's BUILD_CHANNEL name the channel.
 */
enum class UpdateChannel(val id: String) {
    STABLE("stable"),
    NIGHTLY("nightly"),
    ;

    companion object {
        fun fromId(id: String): UpdateChannel? = entries.firstOrNull { channel -> channel.id == id }
    }
}

/** The channel the user follows. Until they choose one it is the channel their build came from. */
interface UpdateChannelPreference {
    suspend fun read(): UpdateChannel

    suspend fun write(channel: UpdateChannel)
}
