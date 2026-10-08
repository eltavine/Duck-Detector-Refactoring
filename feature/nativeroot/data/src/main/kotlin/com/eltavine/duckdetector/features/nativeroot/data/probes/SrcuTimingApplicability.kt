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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import com.eltavine.duckdetector.features.nativeroot.domain.SrcuTimingCollection

internal fun srcuTimingApplicability(apiLevel: Int, kernelRelease: String): SrcuTimingCollection? {
    // Android 11's BasePermission.addToTree stores a copy of the tree's ParsedPermission instead of
    // the supplied info, so the label readback that confirms each synchronous change cannot match.
    // Android 15 moved dynamic permissions to access.abx; API presence alone is insufficient.
    if (apiLevel !in 31..34) return SrcuTimingCollection.UNSUPPORTED_ANDROID
    val match = Regex("^(\\d+)\\.(\\d+)(?:[.-].*)?$").matchEntire(kernelRelease)
        ?: return SrcuTimingCollection.UNSUPPORTED_KERNEL
    val version = match.groupValues[1].toIntOrNull() to match.groupValues[2].toIntOrNull()
    return if (version in setOf(5 to 10, 5 to 15, 6 to 1, 6 to 6, 6 to 12)) null
        else SrcuTimingCollection.UNSUPPORTED_KERNEL
}
