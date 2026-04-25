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

package com.eltavine.duckdetector.features.virtualization.data.probes

import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationNativeBridge
import com.eltavine.duckdetector.features.virtualization.data.native.VirtualizationTrapResult

open class NativeTimingTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runTimingTrap()
}

open class NativeSyscallParityTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runSyscallParityTrap()
}

open class AsmCounterTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runAsmCounterTrap()
}

open class AsmRawSyscallTrapProbe(
    private val nativeBridge: VirtualizationNativeBridge = VirtualizationNativeBridge(),
) {
    open fun probe(): VirtualizationTrapResult = nativeBridge.runAsmRawSyscallTrap()
}
