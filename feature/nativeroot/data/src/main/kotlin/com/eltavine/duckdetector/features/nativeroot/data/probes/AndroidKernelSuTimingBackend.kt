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

package com.eltavine.duckdetector.features.nativeroot.data.probes

import android.content.Context
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import android.system.Os
import com.eltavine.duckdetector.core.platform.PlatformFailureName
import com.eltavine.duckdetector.features.nativeroot.data.native.KernelSuTimingNativeBridge
import com.eltavine.duckdetector.features.nativeroot.domain.KernelSuTimingCpuSnapshot
import java.io.File

internal class AndroidKernelSuTimingBackend(context: Context) : KernelSuTimingBackend {
    private val power = requireNotNull(context.getSystemService(PowerManager::class.java))
    private val bridge = KernelSuTimingNativeBridge()
    override fun supported(): Boolean = Process.is64Bit() && Os.uname().machine == "aarch64" &&
        Process.myUid() % 100000 in 10000..19999 && Os.getuid() == Os.geteuid()
    override fun interactive(): Boolean = power.isInteractive
    override fun elapsedMillis(): Long = SystemClock.elapsedRealtime()
    override fun sample(cpu: Int, preflight: Boolean) = bridge.sample(cpu, preflight)
    override fun cpuSnapshot(): KernelSuTimingCpuSnapshot {
        val failures = mutableListOf<String>()
        fun capture(name: String, read: () -> List<Int>): List<Int>? = try { read() }
            catch (failure: Exception) { failures += "$name: ${PlatformFailureName.of(failure)}"; null }
        fun read(name: String) = KernelSuTimingCpuList.parse(File("/sys/devices/system/cpu/$name").readText())
        // These are sequential snapshots, not a hotplug lock. Each sampling
        // pthread reports its own inherited mask for comparison before binding.
        val present = capture("present") { read("present") }
        val online = capture("online") { read("online") }
        val allowed = capture("affinity") { bridge.affinity() }
        return KernelSuTimingCpuSnapshot(present, online, allowed, failures.joinToString("; "))
    }
}
