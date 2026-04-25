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

package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build

class BinderHookBootstrapProbe {

    fun inspect(): BinderHookBootstrapResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return BinderHookBootstrapResult(
                executed = false,
                detail = "Binder hook bootstrap probe requires Android 12 or newer.",
            )
        }
        return runCatching {
            val installed = KeystoreBinderCaptureHook.installHook()
            BinderHookBootstrapResult(
                executed = true,
                hookInstalled = installed,
                detail = if (installed) {
                    "Binder capture hook bootstrap confirmed."
                } else {
                    "Binder capture hook bootstrap failed."
                },
            )
        }.getOrElse { throwable ->
            BinderHookBootstrapResult(
                executed = true,
                hookInstalled = false,
                detail = throwable.message ?: "Binder hook bootstrap probe failed.",
            )
        }.also {
            KeystoreBinderCaptureHook.restore()
        }
    }
}

data class BinderHookBootstrapResult(
    val executed: Boolean,
    val hookInstalled: Boolean = false,
    val detail: String,
)
