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

package com.eltavine.duckdetector.features.rootmanagers.data.probes.canary

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryLocation
import com.eltavine.duckdetector.features.rootmanagers.domain.InstallerCanaryObservation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** A successful stat adds coordinates; a hidden or denied path never removes owner evidence. */
internal suspend fun InstallerCanaryObservation.withDirectoryObservations(): InstallerCanaryObservation {
    val owner = ownerPackageName ?: return this
    val locations = mutableListOf<InstallerCanaryLocation>()
    val errors = mutableMapOf<Int, Int>()
    for (user in 0..999) {
        currentCoroutineContext().ensureActive()
        try {
            val stat = Os.stat("/data/user_de/$user/$owner")
            if (OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid / 100_000 == user &&
                stat.st_uid % 100_000 in 10_000..19_999) {
                locations += InstallerCanaryLocation(user, stat.st_uid)
            }
        } catch (failure: ErrnoException) {
            errors[failure.errno] = (errors[failure.errno] ?: 0) + 1
        }
    }
    return copy(locations = locations, directoryErrors = errors.toSortedMap())
}
