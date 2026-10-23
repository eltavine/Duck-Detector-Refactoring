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

import java.net.URI

/**
 * Returns an HTTPS download URL that can be handed to an external browser.
 * The update manifest and accelerator selection establish its provenance;
 * this additional scheme check prevents invalid or non-web URI handoffs.
 */
fun httpsUpdateDownloadUrlOrNull(candidate: String?): String? {
    if (candidate.isNullOrBlank()) return null
    val uri = runCatching { URI(candidate) }.getOrNull() ?: return null
    if (!uri.scheme.equals("https", ignoreCase = true) ||
        uri.host.isNullOrBlank() || uri.rawUserInfo != null || uri.port != -1 ||
        uri.rawFragment != null
    ) return null
    return candidate
}
