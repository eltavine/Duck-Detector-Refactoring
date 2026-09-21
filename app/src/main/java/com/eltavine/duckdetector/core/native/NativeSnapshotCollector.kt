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

import kotlin.coroutines.cancellation.CancellationException

/**
 * Runs one native snapshot collection and reports how it ended.
 *
 * Bridges supply three pieces and keep no error handling of their own:
 *  - [readPayload] calls the `external` entry point,
 *  - [parse] turns the payload into a snapshot,
 *  - [unavailable] builds the snapshot to use when neither step produced evidence.
 *
 * The payload type is generic rather than fixed to `String` because not every entry point returns
 * one line-oriented payload: `TeeNativeBridge` reads three, and a bridge may return an array. What
 * matters is only which of the two steps failed, not what shape the evidence arrives in.
 *
 * Because `UnsatisfiedLinkError` is an [Error] rather than an [Exception], the guard has to be a
 * `Throwable` catch. [CancellationException] is rethrown so that a scan cancelled mid-probe still
 * unwinds instead of being recorded as a probe failure.
 */
class NativeSnapshotCollector(
    private val library: NativeLibraryHandle = DuckDetectorNativeLibrary,
) {

    fun <P, T> collect(
        readPayload: () -> P,
        parse: (P) -> T,
        unavailable: (NativeCollectionStatus) -> T,
    ): T {
        if (!library.isLoaded) {
            return unavailable(
                NativeCollectionStatus(
                    outcome = NativeCollectionOutcome.LIBRARY_UNAVAILABLE,
                    detail = library.loadFailureDetail,
                )
            )
        }

        val payload = try {
            readPayload()
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            return unavailable(
                NativeCollectionStatus.failed(NativeCollectionOutcome.BRIDGE_FAILED, failure)
            )
        }

        return try {
            parse(payload)
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Throwable) {
            unavailable(
                NativeCollectionStatus.failed(NativeCollectionOutcome.PAYLOAD_REJECTED, failure)
            )
        }
    }

    companion object {

        val Default: NativeSnapshotCollector = NativeSnapshotCollector()
    }
}
