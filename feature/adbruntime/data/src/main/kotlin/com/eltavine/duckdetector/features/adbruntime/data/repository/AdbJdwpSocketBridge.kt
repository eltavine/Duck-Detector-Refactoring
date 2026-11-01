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

package com.eltavine.duckdetector.features.adbruntime.data.repository

import com.eltavine.duckdetector.core.native.NativeSnapshotCollector

/**
 * One connect() to an AF_UNIX address, reported as errno. The JVM has no API that both accepts an
 * abstract address and preserves errno, so the connect runs natively and only its result crosses
 * the JNI boundary (EVIDENCE.md, "JDWP control socket").
 */
internal class AdbJdwpSocketBridge(
    private val collector: NativeSnapshotCollector = NativeSnapshotCollector.Default,
) {
    fun connectErrno(name: String, abstractName: Boolean): Int? = collector.collect(
        readPayload = { nativeConnectErrno(name, abstractName) },
        parse = { error -> error.takeIf { it >= 0 } },
        unavailable = { null },
    )

    private external fun nativeConnectErrno(name: String, abstractName: Boolean): Int
}
