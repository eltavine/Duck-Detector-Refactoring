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

package com.eltavine.duckdetector.features.mount.data.zygotenext

object ZygoteNextPayloadCodec {

    fun decode(payload: String): ZygoteNextProcessSnapshot {
        val values = linkedMapOf<String, String>()
        val markers = mutableListOf<ZygoteNextMountMarker>()
        payload.lineSequence().filter(String::isNotBlank).forEach { line ->
            val separator = line.indexOf('=')
            require(separator > 0) { "Malformed zygote_next payload line." }
            val key = line.substring(0, separator)
            val value = line.substring(separator + 1)
            if (key == KEY_MARKER) {
                markers += decodeMarker(value)
            } else {
                require(values.put(key, decodeEscaped(value)) == null) {
                    "Duplicate $key in zygote_next payload."
                }
            }
        }

        require(values[KEY_VERSION] == PAYLOAD_VERSION) {
            "Unsupported zygote_next payload version."
        }
        val available = values.requireFlag(KEY_AVAILABLE)
        val mountInfoReadable = values.requireFlag(KEY_MOUNTINFO_READABLE)
        val error = values[KEY_ERROR].orEmpty()
        if (!available || !mountInfoReadable) {
            return ZygoteNextProcessSnapshot(
                available = false,
                errorDetail = error.ifBlank { "Native mountinfo snapshot was unavailable." },
            )
        }

        val pid = values.requireInt(KEY_PID)
        val parentPid = values.requireInt(KEY_PARENT_PID)
        val uid = values.requireInt(KEY_UID)
        val namespaceInode = values.requireLong(KEY_MOUNT_NAMESPACE)
        val rootMountId = values.requireLong(KEY_ROOT_MOUNT_ID)
        val minimumMountId = values.requireLong(KEY_MINIMUM_MOUNT_ID)
        val maximumMountId = values.requireLong(KEY_MAXIMUM_MOUNT_ID)
        val mountCount = values.requireInt(KEY_MOUNT_COUNT)
        require(
            pid > 0 && parentPid >= 0 && uid >= 0 && namespaceInode > 0L &&
                rootMountId > 0L && minimumMountId > 0L && maximumMountId >= minimumMountId &&
                rootMountId in minimumMountId..maximumMountId && mountCount > 0
        ) {
            "Incomplete zygote_next process snapshot."
        }

        return ZygoteNextProcessSnapshot(
            available = true,
            pid = pid,
            parentPid = parentPid,
            uid = uid,
            mountNamespaceInode = namespaceInode,
            rootPropagation = values[KEY_ROOT_PROPAGATION].orEmpty(),
            rootMountId = rootMountId,
            minimumMountId = minimumMountId,
            maximumMountId = maximumMountId,
            mountCount = mountCount,
            markers = markers,
            errorDetail = error,
        )
    }

    private fun decodeMarker(value: String): ZygoteNextMountMarker {
        val fields = value.split('\t')
        require(fields.size == MARKER_FIELD_COUNT) { "Malformed zygote_next marker record." }
        val decoded = fields.map(::decodeEscaped)
        val labels = decoded[0].split(',').filter(String::isNotBlank)
        require(labels.isNotEmpty()) { "Zygote next marker record has no labels." }
        require(decoded.drop(1).all(String::isNotEmpty)) {
            "Zygote next marker record has an empty field."
        }
        return ZygoteNextMountMarker(
            labels = labels,
            mountPoint = decoded[1],
            mountRoot = decoded[2],
            fileSystemType = decoded[3],
            source = decoded[4],
            rawLine = decoded[5],
        )
    }

    internal fun decodeEscaped(value: String): String {
        val output = StringBuilder(value.length)
        var index = 0
        while (index < value.length) {
            val current = value[index]
            if (current != '\\') {
                output.append(current)
                index += 1
                continue
            }
            require(index + 1 < value.length) { "Trailing escape in zygote_next payload." }
            val escaped = value[index + 1]
            output.append(
                when (escaped) {
                    'n' -> '\n'
                    'r' -> '\r'
                    't' -> '\t'
                    '\\' -> '\\'
                    else -> throw IllegalArgumentException(
                        "Unknown escape in zygote_next payload: \\$escaped",
                    )
                },
            )
            index += 2
        }
        return output.toString()
    }

    private fun Map<String, String>.requireFlag(key: String): Boolean {
        return when (val value = get(key)) {
            "1" -> true
            "0" -> false
            else -> throw IllegalArgumentException("Missing or invalid $key in zygote_next payload: $value")
        }
    }

    private fun Map<String, String>.requireInt(key: String): Int {
        return get(key)?.toIntOrNull()
            ?: throw IllegalArgumentException("Missing or invalid $key in zygote_next payload.")
    }

    private fun Map<String, String>.requireLong(key: String): Long {
        return get(key)?.toLongOrNull()
            ?: throw IllegalArgumentException("Missing or invalid $key in zygote_next payload.")
    }

    private const val PAYLOAD_VERSION = "2"
    private const val MARKER_FIELD_COUNT = 6
    private const val KEY_VERSION = "VERSION"
    private const val KEY_AVAILABLE = "AVAILABLE"
    private const val KEY_PID = "PID"
    private const val KEY_PARENT_PID = "PPID"
    private const val KEY_UID = "UID"
    private const val KEY_MOUNT_NAMESPACE = "MOUNT_NAMESPACE"
    private const val KEY_ROOT_PROPAGATION = "ROOT_PROPAGATION"
    private const val KEY_ROOT_MOUNT_ID = "ROOT_MOUNT_ID"
    private const val KEY_MINIMUM_MOUNT_ID = "MIN_MOUNT_ID"
    private const val KEY_MAXIMUM_MOUNT_ID = "MAX_MOUNT_ID"
    private const val KEY_MOUNTINFO_READABLE = "MOUNTINFO_READABLE"
    private const val KEY_MOUNT_COUNT = "MOUNT_COUNT"
    private const val KEY_MARKER = "MARKER"
    private const val KEY_ERROR = "ERROR"
}
