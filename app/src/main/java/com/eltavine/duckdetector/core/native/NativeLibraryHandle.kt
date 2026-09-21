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

package com.eltavine.duckdetector.core.native

/**
 * Load state of the shared native library, injectable so that collection failure paths can be
 * exercised on the JVM where no `.so` exists.
 */
interface NativeLibraryHandle {

    val isLoaded: Boolean

    /** Empty when [isLoaded] is true. */
    val loadFailureDetail: String
}

/**
 * The single load site for `libduckdetector.so`.
 *
 * Every JNI bridge used to run its own `System.loadLibrary` in a companion initialiser, which made
 * the failure invisible: each bridge independently decided that an unloadable library looked the
 * same as a device with nothing to report. Loading here once keeps that decision in one place and
 * lets [NativeSnapshotCollector] name the failure.
 */
object DuckDetectorNativeLibrary : NativeLibraryHandle {

    private const val LIBRARY_NAME = "duckdetector"

    private val loadResult: Result<Unit> = runCatching { System.loadLibrary(LIBRARY_NAME) }

    override val isLoaded: Boolean = loadResult.isSuccess

    override val loadFailureDetail: String = loadResult.exceptionOrNull()
        ?.let { cause ->
            val description = cause.message?.takeIf(String::isNotBlank)
                ?: cause::class.java.simpleName
            "$LIBRARY_NAME could not be loaded: $description"
        }
        .orEmpty()
}
