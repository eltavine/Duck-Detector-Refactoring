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

package com.eltavine.duckdetector.features.nativeroot.data.service

import android.os.IBinder

object ThroneHuntCarrierProtocol {
    const val DESCRIPTOR = "com.eltavine.duckdetector.features.nativeroot.throne_hunt"

    // Setup call: reports the watch descriptor without touching the event stream.
    const val TRANSACTION_COLLECT_SNAPSHOT = IBinder.FIRST_CALL_TRANSACTION + 0

    // Verdict call: the only transaction that reads (and therefore consumes) the event stream.
    const val TRANSACTION_DRAIN_EVENTS = IBinder.FIRST_CALL_TRANSACTION + 1
}
