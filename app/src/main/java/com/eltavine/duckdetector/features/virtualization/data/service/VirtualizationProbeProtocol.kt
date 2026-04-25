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

package com.eltavine.duckdetector.features.virtualization.data.service

import android.os.IBinder

object VirtualizationProbeProtocol {
    const val DESCRIPTOR = "com.eltavine.duckdetector.features.virtualization.probe"
    const val TRANSACTION_COLLECT_SNAPSHOT = IBinder.FIRST_CALL_TRANSACTION + 0
    const val TRANSACTION_IS_NATIVE_AVAILABLE = IBinder.FIRST_CALL_TRANSACTION + 1
    const val TRANSACTION_RUN_SACRIFICIAL_SYSCALL_PACK = IBinder.FIRST_CALL_TRANSACTION + 2
    const val LIST_SEPARATOR = "\u001f"
}
