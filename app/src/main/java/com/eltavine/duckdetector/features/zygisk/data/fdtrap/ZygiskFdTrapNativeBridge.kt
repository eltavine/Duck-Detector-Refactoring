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

package com.eltavine.duckdetector.features.zygisk.data.fdtrap

class ZygiskFdTrapNativeBridge {

    fun isNativeAvailable(): Boolean = nativeLoaded

    fun setupTrapFd(cacheDir: String): Int {
        if (!nativeLoaded) {
            return RESULT_NATIVE_UNAVAILABLE
        }
        return runCatching {
            nativeSetupTrapFd(cacheDir)
        }.getOrElse { RESULT_NATIVE_UNAVAILABLE }
    }

    fun verifyTrapFd(fd: Int): Int {
        if (!nativeLoaded) {
            return RESULT_NATIVE_UNAVAILABLE
        }
        return runCatching {
            nativeVerifyTrapFd(fd)
        }.getOrElse { RESULT_NATIVE_UNAVAILABLE }
    }

    fun getTrapDetails(): String {
        if (!nativeLoaded) {
            return "Native helper unavailable."
        }
        return runCatching {
            nativeGetTrapDetails()
        }.getOrDefault("Trap details unavailable.")
    }

    fun cleanupTrapFd(fd: Int) {
        if (!nativeLoaded) {
            return
        }
        runCatching {
            nativeCleanupTrapFd(fd)
        }
    }

    private external fun nativeSetupTrapFd(cacheDir: String): Int

    private external fun nativeVerifyTrapFd(fd: Int): Int

    private external fun nativeGetTrapDetails(): String

    private external fun nativeCleanupTrapFd(fd: Int)

    companion object {
        const val RESULT_CLEAN = 0
        const val RESULT_EBADF = 1
        const val RESULT_CORRUPTION = 2
        const val RESULT_PROCFS_ANOMALY = 3
        const val RESULT_BIND_FAILED = -2
        const val RESULT_TIMEOUT = -3
        const val RESULT_NATIVE_UNAVAILABLE = -4
        const val RESULT_SKIPPED = -5

        private val nativeLoaded = runCatching { System.loadLibrary("duckdetector") }.isSuccess
    }
}
