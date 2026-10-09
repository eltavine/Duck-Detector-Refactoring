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

package com.eltavine.duckdetector.features.systemproperties.domain

/**
 * One property area's modification time, or why it could not be read.
 *
 * The time only marks the area's last write fault through a shared mapping, read from the coarse
 * wall clock, and no modification is known to leave a particular order, so it is never scored
 * (EVIDENCE.md, "Property area modification times").
 */
sealed interface PropertyAreaMtime {
    /** The area's SELinux property context, which is also its file name. */
    val context: String

    data class Recorded(
        override val context: String,
        val epochSeconds: Long,
        val nanoseconds: Long,
    ) : PropertyAreaMtime

    /** lstat failed; [errno] is its symbolic name, such as EACCES or ENOENT. */
    data class StatFailed(
        override val context: String,
        val errno: String,
    ) : PropertyAreaMtime

    /** The path is not a regular file, so it is not an area init created. */
    data class NotRegularFile(
        override val context: String,
    ) : PropertyAreaMtime
}
