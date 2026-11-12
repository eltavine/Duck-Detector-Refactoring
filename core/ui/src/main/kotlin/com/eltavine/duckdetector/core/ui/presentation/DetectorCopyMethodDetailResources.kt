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

package com.eltavine.duckdetector.core.ui.presentation

import com.eltavine.duckdetector.core.ui.R

internal val detectorCopyMethodDetailResources = mapOf(
    "Analyzes current-thread and synthetic throwable stacks for XposedBridge, LSPosedBridge, LSPHooker_, and related hook callback tokens." to R.string.detector_copy_detail_method_lsposed_stack_analysis,
    "android.os.SystemProperties reflection reads for tracked boot properties." to R.string.detector_copy_detail_method_bootloader_reflection_reads,
    "android.os.SystemProperties reflection reads." to R.string.detector_copy_detail_method_systemproperties_reflection,
    "androidboot.* values from /proc/cmdline and /proc/bootconfig." to R.string.detector_copy_detail_method_bootloader_raw_params,
    "Build.TYPE, Build.TAGS, and Build.FINGERPRINT checks." to R.string.detector_copy_detail_method_systemproperties_build_constants,
    "Builds an off-screen EGL context and inspects GL_VENDOR, GL_RENDERER, and GL_VERSION." to R.string.detector_copy_detail_method_virtualization_egl,
    "Busybox, /data/adb, debug ramdisk payload markers, and hybrid framework path checks." to R.string.detector_copy_detail_method_mount_root_path_markers,
    "Check /proc/kallsyms, /proc/modules, and uname strings for KernelSU, APatch, KernelPatch, SuperCall, or Magisk tokens." to R.string.detector_copy_detail_method_nativeroot_kernel_tokens,
    "Checks ART native bridge properties and translated runtime libraries such as libhoudini, libnb, and libndk_translation." to R.string.detector_copy_detail_method_virtualization_native_bridge,
    "Checks for LSPosed, LSPatch, EdXposed, Xposed installer, TaiChi, VirtualXposed, and common module-manager packages." to R.string.detector_copy_detail_method_lsposed_manager_packages,
    "Checks whether the default uncaught-exception handler class points back to Xposed or LSPosed runtime code." to R.string.detector_copy_detail_method_lsposed_exception_handler,
    "Collects /proc/self/maps, /proc/self/fd, mountinfo, direct device nodes, and raw mount anchors from the current process." to R.string.detector_copy_detail_method_virtualization_process_maps,
    "Cross-source comparison across reflection, getprop, JVM, and native libc reads." to R.string.detector_copy_detail_method_bootloader_cross_source,
    "Direct probes are syscall and side-channel results; indirect probes are kernel strings, paths, processes, properties, and cgroup leakage." to R.string.detector_copy_detail_method_nativeroot_probe_categories,
    "Direct runtime signals come from classes, stack traces, Binder bridges, and native traces; package-only signals are softer residue." to R.string.detector_copy_detail_method_lsposed_evidence_strength,
    "Framework-vs-property, fingerprint-tail, raw-boot, and lock-state coherence checks." to R.string.detector_copy_detail_method_systemproperties_coherence,
    "JNI-backed maps and heap probes for LSPosed-specific runtime evidence." to R.string.detector_copy_detail_method_lsposed_native_probes,
    "JNI-backed native root detection module." to R.string.detector_copy_detail_method_nativeroot_native_module,
    "KernelSU magic prctl probe using option 0xDEADBEEF." to R.string.detector_copy_detail_method_nativeroot_ksu_magic_prctl,
    "Memory-map scan for Zygisk, Riru, and Magisk-hidden library paths." to R.string.detector_copy_detail_method_mount_memory_maps,
    "Mountinfo root-field, propagation, mount-ID, and namespace-consistency checks." to R.string.detector_copy_detail_method_mount_mountinfo,
    "Native libc property cross-checks using the callback-based system property API." to R.string.detector_copy_detail_method_bootloader_native_libc,
    "No kernel identity field had two readable sources, so nothing could be cross-checked." to R.string.detector_copy_detail_method_kernelcheck_no_identity_pair,
    "Overlayfs support, system filesystem type, and suspicious tmpfs sizing checks." to R.string.detector_copy_detail_method_mount_overlayfs,
    "Probes activity and serial Binder services for LSPosed bridge transaction behavior and descriptors." to R.string.detector_copy_detail_method_lsposed_binder_services,
    "Raw-boot, lock-state, partition-verity, and build-profile coherence checks." to R.string.detector_copy_detail_method_bootloader_coherence,
    "Read a small catalog of root-specific properties such as ro.kernel.ksu and APatch/KernelPatch variants." to R.string.detector_copy_detail_method_nativeroot_root_properties,
    "Reflects XposedBridge.disableHooks and XposedBridge.sHookedMethodCallbacks to confirm live bridge state rather than class residue alone." to R.string.detector_copy_detail_method_lsposed_bridge_state,
    "Reports returned statx mount-ID and mount-root fields. Missing fields or syscall errors limit coverage; non-atomic differences do not establish tampering." to R.string.detector_copy_detail_method_mount_statx,
    "Resolve known Xposed, libXposed, and LSPosed runtime classes through boot and app-facing class loaders." to R.string.detector_copy_detail_method_lsposed_class_resolution,
    "Runtime mount table scan for Magisk paths, writable system partitions, overlays, loop devices, and observed source paths." to R.string.detector_copy_detail_method_mount_runtime_table,
    "Samples readable Dalvik heap regions through /proc/self/mem for LSPosed and Xposed keyword residuals." to R.string.detector_copy_detail_method_lsposed_dalvik_heap,
    "Scans /data/local/tmp for temp root exploit artifacts (ksud, temp_su, ksu-helper, ksu-payload, libcve43499root.so). Files matching the CVE-2026-43499 tooling show it was staged on this device; they do not show whether an escalation succeeded or is still active. Paths this process cannot stat leave the check unavailable." to R.string.detector_copy_detail_method_nativeroot_temp_root_artifacts,
    "Scans /proc/self/maps for LSPosed, XposedBridge, libXposed, LSPlant, EdXposed, and LSPatch runtime mappings." to R.string.detector_copy_detail_method_lsposed_proc_maps,
    "Scans installed app manifest meta-data such as xposedmodule, xposedminversion, and xposedscope." to R.string.detector_copy_detail_method_lsposed_module_metadata,
    "Single getprop dump parsed once and reused for cross-checks." to R.string.detector_copy_detail_method_systemproperties_getprop,
    "Single getprop dump reused for cross-source comparisons." to R.string.detector_copy_detail_method_bootloader_getprop_dump,
    "System.getProperty fallback reads." to R.string.detector_copy_detail_method_systemproperties_jvm,
    "Tracked boot, AVB, dm-verity, Samsung fuse, and secure-build properties." to R.string.detector_copy_detail_method_bootloader_tracked_properties,
    "Transparent NativeActivity launcher runs early namespace and mount checks before MainActivity starts." to R.string.detector_copy_detail_method_mount_early_launcher,
    "Walks app-facing ClassLoader parent chains and flags loader names or chain depth that resemble LSPosed/Xposed injection." to R.string.detector_copy_detail_method_lsposed_classloader_chain,
)
