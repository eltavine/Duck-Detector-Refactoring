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

import com.eltavine.duckdetector.features.update.domain.GitHubAcceleration

/**
 * How update requests and the update download reach GitHub. gh-proxy.com fetches the GitHub URL
 * written after its own address and returns that response, release assets included:
 * https://gh-proxy.com/docs/github-accelerator
 */
internal enum class GitHubRoute {
    DIRECT,
    GH_PROXY,
    ;

    fun url(gitHubUrl: String): String = when (this) {
        DIRECT -> gitHubUrl
        GH_PROXY -> GH_PROXY_PREFIX + gitHubUrl
    }

    /**
     * gh-proxy.com's firewall answers 403 to every path containing the `...` between a comparison's
     * base and head, escaped or not, so only a direct check can compare commits.
     */
    val comparesCommits: Boolean
        get() = this == DIRECT

    companion object {
        fun of(acceleration: GitHubAcceleration): GitHubRoute =
            if (acceleration == GitHubAcceleration.ENABLED) GH_PROXY else DIRECT
    }
}

private const val GH_PROXY_PREFIX = "https://gh-proxy.com/"
