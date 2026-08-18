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

package com.eltavine.duckdetector.features.bootloader.data.widevine

internal fun interface WidevineNativePropertyReader {
    fun readProperties(): WidevineNativeSnapshot
}

internal class WidevineNativeBridge : WidevineNativePropertyReader {

    override fun readProperties(): WidevineNativeSnapshot {
        return try {
            parse(nativeReadProperties())
        } catch (_: LinkageError) {
            WidevineNativeSnapshot()
        } catch (_: Exception) {
            WidevineNativeSnapshot()
        }
    }

    internal fun parse(raw: Array<String?>): WidevineNativeSnapshot {
        if (raw.size < PAYLOAD_FIELD_COUNT || raw[INDEX_AVAILABLE] != "1") {
            return WidevineNativeSnapshot()
        }

        val securityStatus = raw[INDEX_SECURITY_STATUS].toStatusCode()
        val systemIdStatus = raw[INDEX_SYSTEM_ID_STATUS].toStatusCode()
        if (securityStatus == MEDIA_ERROR_INVALID_OBJECT &&
            systemIdStatus == MEDIA_ERROR_INVALID_OBJECT
        ) {
            return WidevineNativeSnapshot(
                securityLevelStatusCode = securityStatus,
                systemIdStatusCode = systemIdStatus,
            )
        }
        return WidevineNativeSnapshot(
            available = true,
            securityLevel = propertyRead(securityStatus, raw[INDEX_SECURITY_VALUE]),
            systemId = propertyRead(systemIdStatus, raw[INDEX_SYSTEM_ID_VALUE]),
            securityLevelStatusCode = securityStatus,
            systemIdStatusCode = systemIdStatus,
        )
    }

    private fun propertyRead(statusCode: Int?, value: String?): WidevinePropertyRead {
        return when {
            statusCode == MEDIA_STATUS_OK && value?.isValidWidevinePropertyValue() == true ->
                WidevinePropertyRead(
                    status = WidevinePropertyStatus.AVAILABLE,
                    value = value,
                )

            statusCode == MEDIA_ERROR_UNSUPPORTED ||
                statusCode == MEDIA_ERROR_INVALID_PARAMETER ->
                WidevinePropertyRead(WidevinePropertyStatus.UNSUPPORTED)

            else -> WidevinePropertyRead(WidevinePropertyStatus.ERROR)
        }
    }

    private fun String?.toStatusCode(): Int? = this?.toIntOrNull()

    private external fun nativeReadProperties(): Array<String?>

    private companion object {
        const val MEDIA_STATUS_OK = 0
        const val MEDIA_ERROR_UNSUPPORTED = -10002
        const val MEDIA_ERROR_INVALID_OBJECT = -10003
        // NdkMediaDrm maps DRM_CANNOT_HANDLE (including unknown vendor properties) to this code.
        const val MEDIA_ERROR_INVALID_PARAMETER = -10004
        const val PAYLOAD_FIELD_COUNT = 5
        const val INDEX_AVAILABLE = 0
        const val INDEX_SECURITY_STATUS = 1
        const val INDEX_SECURITY_VALUE = 2
        const val INDEX_SYSTEM_ID_STATUS = 3
        const val INDEX_SYSTEM_ID_VALUE = 4

        init {
            try {
                System.loadLibrary("duckdetector")
            } catch (_: LinkageError) {
                // The Java MediaDrm path remains available when the optional native path cannot load.
            } catch (_: SecurityException) {
                // A runtime loading policy can disable parity collection without disabling the probe.
            }
        }
    }
}
