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

package com.eltavine.duckdetector.features.update.data

import com.eltavine.duckdetector.features.update.domain.UpdateChannel

internal object UpdateEndpoints {
    const val REPOSITORY_PATH = "/eltavine/Duck-Detector-Refactoring"
    const val WEB_REPOSITORY = "https://github.com$REPOSITORY_PATH"
    const val API_REPOSITORY = "https://api.github.com/repos/eltavine/Duck-Detector-Refactoring"
    const val NIGHTLY_TAG = "nightly"
    const val NIGHTLY_MANIFEST_URL = "$WEB_REPOSITORY/releases/download/$NIGHTLY_TAG/update.json"

    /**
     * GitHub redirects this to the newest published full release. The Nightly release is a
     * prerelease and drafts are unpublished, so that release is always the latest Stable one.
     */
    const val STABLE_MANIFEST_URL = "$WEB_REPOSITORY/releases/latest/download/update.json"

    fun manifestUrl(channel: UpdateChannel): String = when (channel) {
        UpdateChannel.STABLE -> STABLE_MANIFEST_URL
        UpdateChannel.NIGHTLY -> NIGHTLY_MANIFEST_URL
    }
}
