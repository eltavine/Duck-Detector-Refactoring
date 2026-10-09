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

package com.eltavine.duckdetector.features.systemproperties.data.repository

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.eltavine.duckdetector.features.systemproperties.domain.PropertyAreaMtime

/**
 * Records the modification times of the debug, radio and system property areas. Like the native
 * area scan, it does not follow symlinks and only accepts regular files.
 */
internal class PropertyAreaMtimeProbe {

    fun read(): List<PropertyAreaMtime> = CONTEXTS.map(::read)

    private fun read(context: String): PropertyAreaMtime {
        val stat = try {
            Os.lstat("$PROPERTY_AREA_DIR/$context")
        } catch (error: ErrnoException) {
            return PropertyAreaMtime.StatFailed(
                context = context,
                errno = OsConstants.errnoName(error.errno) ?: error.errno.toString(),
            )
        }
        if (!OsConstants.S_ISREG(stat.st_mode)) {
            return PropertyAreaMtime.NotRegularFile(context)
        }
        return PropertyAreaMtime.Recorded(
            context = context,
            epochSeconds = stat.st_mtim.tv_sec,
            nanoseconds = stat.st_mtim.tv_nsec,
        )
    }

    private companion object {
        const val PROPERTY_AREA_DIR = "/dev/__properties__"
        val CONTEXTS = listOf(
            "u:object_r:debug_prop:s0",
            "u:object_r:radio_prop:s0",
            "u:object_r:system_prop:s0",
        )
    }
}
