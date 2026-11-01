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

package com.eltavine.duckdetector.features.networkrisk.data.modules

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import com.eltavine.duckdetector.features.networkrisk.domain.*
import java.io.IOException

/** These independent entries identify deployment metadata, never the core or running service. */
internal class Box4MagiskCollector {
    fun collect(): ProxyModuleEvidence = ProxyModuleEvidence(
        ProxyDeployment.BOX4MAGISK,
        readModuleMetadata("/data/adb/modules/box4/module.prop", "box4"),
    )
}

internal class BoxForRootCollector {
    fun collect(): ProxyModuleEvidence = ProxyModuleEvidence(
        ProxyDeployment.BOX_FOR_ROOT,
        readModuleMetadata("/data/adb/modules/box_for_root/module.prop", "box_for_root"),
    )
}

/** Shared bounded metadata operation; does not traverse directories or read proxy configurations. */
private fun readModuleMetadata(path: String, expectedId: String): NetworkObservation<String> {
    var descriptor: java.io.FileDescriptor? = null
    return try {
        val opened = Os.open(path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW or OsConstants.O_NONBLOCK, 0)
        descriptor = opened
        if (!OsConstants.S_ISREG(Os.fstat(opened).st_mode)) {
            NetworkObservation.unavailable(ProbeFailure.INVALID_METADATA)
        } else {
            val buffer = ByteArray(4097)
            var used = 0
            while (used < buffer.size) {
                val count = Os.read(opened, buffer, used, buffer.size - used)
                if (count <= 0) break
                used += count
            }
            val bytes = buffer.copyOf(used)
            if (bytes.size > 4096) NetworkObservation.unavailable(ProbeFailure.READ_LIMIT)
            else parseModuleMetadata(bytes.toString(Charsets.UTF_8), expectedId)
        }
    } catch (failure: ErrnoException) {
        when (failure.errno) {
            OsConstants.EACCES, OsConstants.EPERM -> NetworkObservation(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED)
            OsConstants.ENOENT, OsConstants.ENOTDIR -> NetworkObservation.absent()
            else -> NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE)
        }
    } catch (_: SecurityException) {
        NetworkObservation(ObservationState.PERMISSION_LIMITED, failure = ProbeFailure.ACCESS_DENIED)
    } catch (_: IOException) {
        NetworkObservation.unavailable(ProbeFailure.PLATFORM_FAILURE)
    } finally {
        descriptor?.let { try { Os.close(it) } catch (_: ErrnoException) { } }
    }
}

internal fun parseModuleMetadata(text: String, expectedId: String): NetworkObservation<String> {
    val fields = text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { it.split('=', limit = 2) }.filter { it.size == 2 }.groupBy({ it[0].trim() }, { it[1].trim() })
    val version = fields["version"]?.singleOrNull()
    return if (fields["id"]?.singleOrNull() == expectedId && version != null && Regex("[A-Za-z0-9._+-]{1,64}").matches(version)) {
        NetworkObservation.observed(version)
    } else NetworkObservation(ObservationState.INCONCLUSIVE, failure = ProbeFailure.INVALID_METADATA)
}
