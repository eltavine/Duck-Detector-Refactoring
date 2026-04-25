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

package com.eltavine.duckdetector.features.customrom.data.repository

import com.eltavine.duckdetector.features.customrom.data.native.CustomRomNativeSnapshot
import com.eltavine.duckdetector.features.customrom.data.rules.CustomRomCatalog
import com.eltavine.duckdetector.features.customrom.domain.CustomRomFinding

internal object CustomRomPlatformFileResolver {

    fun resolve(
        nativeSnapshot: CustomRomNativeSnapshot,
        isPixel: Boolean,
        shouldSkip: (String, Boolean) -> Boolean,
        fileExists: (String) -> Boolean,
    ): List<CustomRomFinding> {
        if (nativeSnapshot.available) {
            return nativeSnapshot.platformFiles.filterNot { shouldSkip(it.romName, isPixel) }
        }

        return CustomRomCatalog.platformFileSignatures.mapNotNull { signature ->
            if (shouldSkip(signature.romName, isPixel) || !fileExists(signature.path)) {
                return@mapNotNull null
            }
            CustomRomFinding(
                romName = signature.romName,
                signal = signature.path.substringAfterLast('/'),
                detail = signature.path,
            )
        }.distinct()
    }
}
