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

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.R

private val detectorCopyLabelResources = mapOf(
    "@ mentions" to R.string.detector_copy_label_mentions,
    "Activity bridge exception" to R.string.detector_copy_label_activity_bridge_exception,
    "Activity bridge throwable" to R.string.detector_copy_label_activity_bridge_throwable,
    "Activity service bridge" to R.string.detector_copy_label_activity_service_bridge,
    "ADB AUTH token" to R.string.detector_copy_label_adb_auth_token,
    "ADB CNXN banner" to R.string.detector_copy_label_adb_cnxn_banner,
    "ADB init socket vs init" to R.string.detector_copy_label_adb_init_socket_vs_init,
    "ADB JDWP socket vs init" to R.string.detector_copy_label_adb_jdwp_socket_vs_init,
    "ADB protocol vs init" to R.string.detector_copy_label_adb_protocol_vs_init,
    "ADB STLS request" to R.string.detector_copy_label_adb_stls_request,
    "Anonymous device minors" to R.string.detector_copy_label_anonymous_device_minors,
    "API level" to R.string.detector_copy_label_api_level,
    "Arguments" to R.string.detector_copy_label_heap_arguments,
    "Application UID mismatch" to R.string.detector_copy_label_application_uid_mismatch,
    "ARM64 CPU identity" to R.string.detector_copy_label_arm64_cpu_identity,
    "ARM64 native hook" to R.string.detector_copy_label_arm64_native_hook,
    "ASM honeypots" to R.string.detector_copy_label_asm_honeypots,
    "Attestation chain" to R.string.detector_copy_label_attestation_chain,
    "Attestation tier" to R.string.detector_copy_label_attestation_tier,
    "Attestation" to R.string.detector_copy_label_tee_attestation,
    "Attestation boot hash" to R.string.detector_copy_label_attested_boot_hash,
    "Attestation boot key" to R.string.detector_copy_label_attested_boot_key,
    "Attestation boot state" to R.string.detector_copy_label_attested_boot_state,
    "Attestation deviceLocked" to R.string.detector_copy_label_attested_device_locked,
    "Attestation hash vs vbmeta digest" to R.string.detector_copy_label_attested_hash_vs_vbmeta_digest,
    "AVC denial leak" to R.string.detector_copy_label_avc_denial_leak,
    "AVC side-channel" to R.string.detector_copy_label_avc_side_channel,
    "Boot cmdline" to R.string.detector_copy_label_boot_cmdline,
    "Boot consistency" to R.string.detector_copy_label_boot_consistency,
    "Boot raw" to R.string.detector_copy_label_boot_raw,
    "Boot state" to R.string.detector_copy_label_boot_state,
    "Build" to R.string.detector_copy_label_build,
    "Cache access" to R.string.detector_copy_label_location_cache_access,
    "Cached mock marks" to R.string.detector_copy_label_location_cached_mock_marks,
    "Build constants" to R.string.detector_copy_label_build_constants,
    "Build fields" to R.string.detector_copy_label_build_fields,
    "Build fields checked" to R.string.detector_copy_label_build_fields_checked,
    "Certificate chain" to R.string.detector_copy_label_certificate_chain,
    "Certificate trust" to R.string.detector_copy_label_certificate_trust,
    "Certificates" to R.string.detector_copy_label_certificates,
    "Cgroup UID mismatch" to R.string.detector_copy_label_cgroup_uid_mismatch,
    "Chinese glyphs" to R.string.detector_copy_label_chinese_glyphs,
    "Class loading anomalies" to R.string.detector_copy_label_class_loading_anomalies,
    "ClassLoader chain" to R.string.detector_copy_label_classloader_chain,
    "ClassLoader token" to R.string.detector_copy_label_classloader_token,
    "Classpath/source mismatch" to R.string.detector_copy_label_classpath_source_mismatch,
    "Cmdline rules checked" to R.string.detector_copy_label_cmdline_rules_checked,
    "Confidence" to R.string.detector_copy_label_confidence,
    "Consistency hits" to R.string.detector_copy_label_consistency_hits,
    "Cross-check rules" to R.string.detector_copy_label_cross_check_rules,
    "Cross-checks" to R.string.detector_copy_label_cross_checks,
    "Cross-process artifact drift" to R.string.detector_copy_label_cross_process_artifact_drift,
    "Cross-process consistency" to R.string.detector_copy_label_cross_process_consistency,
    "Cross-process helper" to R.string.detector_copy_label_cross_process_helper,
    "Cross-process mount anchor drift" to R.string.detector_copy_label_cross_process_mount_anchor_drift,
    "Cross-process mount views" to R.string.detector_copy_label_cross_process_mount_views,
    "Cross-process namespace drift" to R.string.detector_copy_label_cross_process_namespace_drift,
    "Cross-process path drift" to R.string.detector_copy_label_cross_process_path_drift,
    "Coverage and privacy" to R.string.detector_copy_title_location_coverage_privacy,
    "Current package missing from UID" to R.string.detector_copy_label_current_package_missing_from_uid,
    "Current thread stack" to R.string.detector_copy_label_current_thread_stack,
    "Custom identifiers" to R.string.detector_copy_label_custom_identifiers,
    "CVE patch state" to R.string.detector_copy_label_cve_patch_state,
    "Daemon paths checked" to R.string.detector_copy_label_daemon_paths_checked,
    "Danger findings" to R.string.detector_copy_label_danger_findings,
    "Dangerous types" to R.string.detector_copy_label_dangerous_types,
    "Default exception handler" to R.string.detector_copy_label_default_exception_handler,
    "Detection path" to R.string.detector_copy_label_detection_path,
    "Dex and classpath" to R.string.detector_copy_label_dex_and_classpath,
    "Dex path hits" to R.string.detector_copy_label_dex_path_hits,
    "Dex paths" to R.string.detector_copy_label_dex_paths,
    "EGL renderer" to R.string.detector_copy_label_egl_renderer,
    "Emoji markers" to R.string.detector_copy_label_emoji_markers,
    "Emulator hardware props" to R.string.detector_copy_label_emulator_hardware_props,
    "Environment hits" to R.string.detector_copy_label_environment_hits,
    "Environment variables" to R.string.detector_copy_label_environment_variables,
    "Fake tcontext" to R.string.detector_copy_label_fake_tcontext,
    "FD entries" to R.string.detector_copy_label_fd_entries,
    "FD trap" to R.string.detector_copy_label_fd_trap,
    "File descriptors" to R.string.detector_copy_label_file_descriptors,
    "Filesystem" to R.string.detector_copy_label_filesystem,
    "Filesystem probes" to R.string.detector_copy_label_filesystem_probes,
    "fsnotifySrcuCloseTiming" to R.string.detector_copy_label_fsnotify_srcu_close_timing,
    "Generic build tokens" to R.string.detector_copy_label_generic_build_tokens,
    "getprop hits" to R.string.detector_copy_label_getprop_hits,
    "propertyScan" to R.string.detector_copy_label_property_scan,
    "buildFieldScan" to R.string.detector_copy_label_build_field_scan,
    "modificationScan" to R.string.detector_copy_label_modification_scan,
    "packageScan" to R.string.detector_copy_label_package_scan,
    "serviceScan" to R.string.detector_copy_label_service_scan,
    "reflectionScan" to R.string.detector_copy_label_reflection_scan,
    "mapsInjection" to R.string.detector_copy_label_maps_injection,
    "nativeFiles" to R.string.detector_copy_label_native_files,
    "nativePolicy" to R.string.detector_copy_label_native_policy,
    "nativeSymbols" to R.string.detector_copy_label_native_symbols,
    "daemonScan" to R.string.detector_copy_label_daemon_scan,
    "fileScan" to R.string.detector_copy_label_file_scan,
    "nativeSyscall" to R.string.detector_copy_label_native_syscall,
    "nativeLibrary" to R.string.detector_copy_label_native_library,
    "getprop snapshot" to R.string.detector_copy_label_getprop_snapshot,
    "Graphics renderer" to R.string.detector_copy_label_graphics_renderer,
    "Hard findings" to R.string.detector_copy_label_hard_findings,
    "Hardware-backed" to R.string.detector_copy_label_hardware_backed,
    "Heuristic signals" to R.string.detector_copy_label_heuristic_signals,
    "Honeypot hits" to R.string.detector_copy_label_honeypot_hits,
    "Host apps" to R.string.detector_copy_label_host_apps,
    "Host dex path" to R.string.detector_copy_label_host_dex_path,
    "Host package shares UID" to R.string.detector_copy_label_host_package_shares_uid,
    "Hypervisor capability" to R.string.detector_copy_label_hypervisor_capability,
    "Identity sources" to R.string.detector_copy_label_identity_sources,
    "Info findings" to R.string.detector_copy_label_info_findings,
    "Info props" to R.string.detector_copy_label_info_props,
    "Init namespace access" to R.string.detector_copy_label_init_namespace_access,
    "init.rc hook timing" to R.string.detector_copy_label_init_rc_hook_timing,
    "Isolated consistency" to R.string.detector_copy_label_isolated_consistency,
    "Isolated helper" to R.string.detector_copy_label_isolated_helper,
    "Isolated mount anchor drift" to R.string.detector_copy_label_isolated_mount_anchor_drift,
    "Isolated mount namespace drift" to R.string.detector_copy_label_isolated_mount_namespace_drift,
    "Isolated namespace drift" to R.string.detector_copy_label_isolated_namespace_drift,
    "Isolated process stayed clean" to R.string.detector_copy_label_isolated_process_stayed_clean,
    "Isolated-process consistency" to R.string.detector_copy_label_isolated_process_consistency,
    "Issues" to R.string.detector_copy_label_issues,
    "java app_zygote" to R.string.detector_copy_label_java_app_zygote,
    "JVM fallback" to R.string.detector_copy_label_jvm_fallback,
    "JVM hits" to R.string.detector_copy_label_jvm_hits,
    "JVM property fallback" to R.string.detector_copy_label_jvm_property_fallback,
    "Kernel identity sources" to R.string.detector_copy_label_kernel_identity_sources,
    "Kernel major version" to R.string.detector_copy_label_kernel_major_version,
    "Kernel pointers" to R.string.detector_copy_label_kernel_pointers,
    "KernelSU file read" to R.string.detector_copy_label_kernelsu_file_read,
    "KernelSU manager manifest" to R.string.detector_copy_label_kernelsu_manager_manifest,
    "Key Attestation" to R.string.detector_copy_label_key_attestation,
    "Keyword families checked" to R.string.detector_copy_label_keyword_families_checked,
    "KSU supercall" to R.string.detector_copy_label_ksu_supercall,
    "Launcher enumeration" to R.string.detector_copy_label_launcher_enumeration,
    "Local contracts" to R.string.detector_copy_label_location_local_contracts,
    "App-owned Location contracts" to R.string.detector_copy_title_location_app_owned_contracts,
    "Optional cached location context" to R.string.detector_copy_title_location_cached_context,
    "Reference project package" to R.string.detector_copy_title_location_reference_project_package,
    "Setter / getter round trip" to R.string.detector_copy_label_location_setter_getter_round_trip,
    "Optional field flags" to R.string.detector_copy_label_location_optional_field_flags,
    "Reset semantics" to R.string.detector_copy_label_location_reset_semantics,
    "Synthetic mock flag round trip" to R.string.detector_copy_label_location_synthetic_mock_flag_round_trip,
    "VirtualLocation package" to R.string.detector_copy_label_location_virtual_location_package,
    "Observation boundary" to R.string.detector_copy_label_location_observation_boundary,
    "Legitimate contexts" to R.string.detector_copy_label_location_legitimate_contexts,
    "Data budget" to R.string.detector_copy_label_location_data_budget,
    "Cache collection" to R.string.detector_copy_label_location_cache_collection,
    "Spoof control" to R.string.detector_copy_label_pif_spoof_control,
    "Pixel props" to R.string.detector_copy_label_pif_pixel_props,
    "Device spoof" to R.string.detector_copy_label_pif_device_spoof,
    "Security spoof" to R.string.detector_copy_label_pif_security_spoof,
    "Reflection/getprop/native alignment" to R.string.detector_copy_label_pif_reflection_alignment,
    "Maps runtime trace" to R.string.detector_copy_label_pif_maps_runtime_trace,
    "Native libc residue" to R.string.detector_copy_label_pif_native_libc_residue,
    "Apps checked" to R.string.detector_copy_label_apps_checked,
    "Candidate permission owner" to R.string.detector_copy_label_candidate_permission_owner,
    "Concealed" to R.string.detector_copy_label_concealed,
    "Enumeration" to R.string.detector_copy_label_enumeration,
    "Evidence scope" to R.string.detector_copy_label_evidence_scope,
    "Installer permission probe" to R.string.detector_copy_label_installer_permission_probe,
    "Launcher self-check" to R.string.detector_copy_label_launcher_self_check,
    "Matches" to R.string.detector_copy_label_matches,
    "Matched apps" to R.string.detector_copy_label_matched_apps,
    "Owner directory coordinates" to R.string.detector_copy_label_owner_directory_coordinates,
    "Profiles" to R.string.detector_copy_label_profiles,
    "Legacy Xposed API" to R.string.detector_copy_label_legacy_xposed_api,
    "libXposed API" to R.string.detector_copy_label_libxposed_api,
    "Local ADB service" to R.string.detector_copy_label_local_adb_service,
    "Local legacy ADB TCP service" to R.string.detector_copy_label_local_legacy_adb_tcp_service,
    "Local Wireless ADB TLS service" to R.string.detector_copy_label_local_wireless_adb_tls_service,
    "Lock state" to R.string.detector_copy_label_lock_state,
    "Log tag" to R.string.detector_copy_label_log_tag,
    "Logcat direct hit" to R.string.detector_copy_label_logcat_direct_hit,
    "Logcat pattern" to R.string.detector_copy_label_logcat_pattern,
    "Logcat process" to R.string.detector_copy_label_logcat_process,
    "Logcat tag" to R.string.detector_copy_label_logcat_tag,
    "Logcat tag filter" to R.string.detector_copy_label_logcat_tag_filter,
    "Logcat tag prefix" to R.string.detector_copy_label_logcat_tag_prefix,
    "LSPosed file read" to R.string.detector_copy_label_lsposed_file_read,
    "LSPosed service classes" to R.string.detector_copy_label_lsposed_service_classes,
    "signing certificate" to R.string.detector_copy_label_signing_certificate,
    "native payload" to R.string.detector_copy_label_native_payload,
    "package name" to R.string.detector_copy_label_package_name,
    "application class" to R.string.detector_copy_label_application_class,
    "application class name" to R.string.detector_copy_label_application_class_name,
    "zygote preload" to R.string.detector_copy_label_zygote_preload,
    "label" to R.string.detector_copy_label_anchor_label,
    "launcher class" to R.string.detector_copy_label_launcher_class,
    "MAC active" to R.string.detector_copy_label_mac_active,
    "Magisk binder" to R.string.detector_copy_label_magisk_binder,
    "Maps scanned" to R.string.detector_copy_label_maps_scanned,
    "Minor device observation" to R.string.detector_copy_label_minor_device_observation,
    "mntent strings residue" to R.string.detector_copy_label_mntent_strings_residue,
    "Mode" to R.string.detector_copy_label_mode,
    "Modification" to R.string.detector_copy_label_modification,
    "Modification props checked" to R.string.detector_copy_label_modification_props_checked,
    "Modified functions" to R.string.detector_copy_label_modified_functions,
    "Module directory" to R.string.detector_copy_label_module_directory,
    "Module metadata" to R.string.detector_copy_label_module_metadata,
    "Mount anchor drift" to R.string.detector_copy_label_mount_anchor_drift,
    "Mount namespace" to R.string.detector_copy_label_mount_namespace,
    "Mountinfo lines" to R.string.detector_copy_label_mountinfo_lines,
    "Named services checked" to R.string.detector_copy_label_named_services_checked,
    "Native" to R.string.detector_copy_label_native,
    "native app_zygote" to R.string.detector_copy_label_native_app_zygote,
    "Native bridge" to R.string.detector_copy_label_native_bridge,
    "Native hits" to R.string.detector_copy_label_native_hits,
    "Native honeypots" to R.string.detector_copy_label_native_honeypots,
    "Native hook" to R.string.detector_copy_label_native_hook,
    "Native libc" to R.string.detector_copy_label_native_libc,
    "Native libc props" to R.string.detector_copy_label_native_libc_props,
    "Native library" to R.string.detector_copy_label_native_library,
    "Native maps" to R.string.detector_copy_label_native_maps,
    "Native payload directories" to R.string.detector_copy_label_native_payload_directories,
    "Native prop hits" to R.string.detector_copy_label_native_prop_hits,
    "Native traces" to R.string.detector_copy_label_native_traces,
    "Network" to R.string.detector_copy_label_network,
    "No contradiction established" to R.string.detector_copy_label_no_contradiction_established,
    "Not established" to R.string.detector_copy_label_not_established,
    "Not observable" to R.string.detector_copy_label_not_observable,
    "Other language scripts" to R.string.detector_copy_label_other_language_scripts,
    "Overlayfs kernel support" to R.string.detector_copy_label_overlayfs_kernel_support,
    "Package visibility" to R.string.detector_copy_label_package_visibility,
    "Reference package" to R.string.detector_copy_label_location_reference_package,
    "Packages" to R.string.detector_copy_label_packages,
    "Packages checked" to R.string.detector_copy_label_packages_checked,
    "Path coverage" to R.string.detector_copy_label_path_coverage,
    "Path probes" to R.string.detector_copy_label_path_probes,
    "Props" to R.string.detector_copy_label_props,
    "Peer group observation" to R.string.detector_copy_label_peer_group_observation,
    "Pending module update" to R.string.detector_copy_label_pending_module_update,
    "Permissive domains" to R.string.detector_copy_label_permissive_domains,
    "Persistent contradiction" to R.string.detector_copy_label_persistent_contradiction,
    "Policy enforced" to R.string.detector_copy_label_policy_enforced,
    "Policy version" to R.string.detector_copy_label_policy_version,
    "Preload context" to R.string.detector_copy_label_preload_context,
    "Prepended third-party dex" to R.string.detector_copy_label_prepended_third_party_dex,
    "Present (label denied)" to R.string.detector_copy_label_present_label_denied,
    "Present, init reports stopped" to R.string.detector_copy_label_present_init_stopped,
    "Probe path" to R.string.detector_copy_label_probe_path,
    "Proc contexts checked" to R.string.detector_copy_label_proc_contexts_checked,
    "Proc inode timestamps" to R.string.detector_copy_label_proc_inode_timestamps,
    "Proc reads denied" to R.string.detector_copy_label_proc_reads_denied,
    "Process context" to R.string.detector_copy_label_process_context,
    "Profiles searched" to R.string.detector_copy_label_profiles_searched,
    "Traces" to R.string.detector_copy_label_heap_traces,
    "Snapshot" to R.string.detector_copy_label_heap_snapshot,
    "Prop area anomalies" to R.string.detector_copy_label_prop_area_anomalies,
    "Prop area contexts" to R.string.detector_copy_label_prop_area_contexts,
    "Prop area holes" to R.string.detector_copy_label_prop_area_holes,
    "Prop area layout" to R.string.detector_copy_label_prop_area_layout,
    "Prop areas scanned" to R.string.detector_copy_label_prop_areas_scanned,
    "Prop item anomalies" to R.string.detector_copy_label_prop_item_anomalies,
    "Properties and build" to R.string.detector_copy_label_properties_and_build,
    "Properties checked" to R.string.detector_copy_label_properties_checked,
    "Properties observed" to R.string.detector_copy_label_properties_observed,
    "Property catalog" to R.string.detector_copy_label_property_catalog,
    "Property hits" to R.string.detector_copy_label_property_hits,
    "QEMU guest properties" to R.string.detector_copy_label_qemu_guest_properties,
    "qemud service" to R.string.detector_copy_label_qemud_service,
    "Raw boot hits" to R.string.detector_copy_label_raw_boot_hits,
    "Raw boot params" to R.string.detector_copy_label_raw_boot_params,
    "Reason" to R.string.detector_copy_label_reason,
    "Reflection" to R.string.detector_copy_label_reflection,
    "Reflection API" to R.string.detector_copy_label_reflection_api,
    "Reflection hits" to R.string.detector_copy_label_reflection_hits,
    "Required since" to R.string.detector_copy_label_required_since,
    "Residue paths" to R.string.detector_copy_label_residue_paths,
    "Review findings" to R.string.detector_copy_label_review_findings,
    "ROMs" to R.string.detector_copy_label_roms,
    "Root daemons" to R.string.detector_copy_label_root_daemons,
    "Root mount exposure" to R.string.detector_copy_label_root_mount_exposure,
    "Rules checked" to R.string.detector_copy_label_rules_checked,
    "Rules observed" to R.string.detector_copy_label_rules_observed,
    "Runtime" to R.string.detector_copy_label_runtime,
    "Runtime artifacts" to R.string.detector_copy_label_runtime_artifacts,
    "Runtime hits" to R.string.detector_copy_label_runtime_hits,
    "Runtime markers" to R.string.detector_copy_label_runtime_markers,
    "Sacrificial syscall pack" to R.string.detector_copy_label_sacrificial_syscall_pack,
    "Security classes" to R.string.detector_copy_label_security_classes,
    "Selective cgroup visibility" to R.string.detector_copy_label_selective_cgroup_visibility,
    "Self context" to R.string.detector_copy_label_self_context,
    "SEPolicy patch" to R.string.detector_copy_label_sepolicy_patch,
    "Serial bridge exception" to R.string.detector_copy_label_serial_bridge_exception,
    "Serial bridge throwable" to R.string.detector_copy_label_serial_bridge_throwable,
    "Serial service bridge" to R.string.detector_copy_label_serial_service_bridge,
    "Serial service descriptor" to R.string.detector_copy_label_serial_service_descriptor,
    "Service script" to R.string.detector_copy_label_service_script,
    "Services" to R.string.detector_copy_label_services,
    "Services listed" to R.string.detector_copy_label_services_listed,
    "Shell tmp API mismatch" to R.string.detector_copy_label_shell_tmp_api_mismatch,
    "Shell tmp dedicated mount" to R.string.detector_copy_label_shell_tmp_dedicated_mount,
    "Shell tmp inode" to R.string.detector_copy_label_shell_tmp_inode,
    "Shell tmp mode" to R.string.detector_copy_label_shell_tmp_mode,
    "Shell tmp ownership" to R.string.detector_copy_label_shell_tmp_ownership,
    "Shell tmp view" to R.string.detector_copy_label_shell_tmp_view,
    "Signing certificates" to R.string.detector_copy_label_signing_certificates,
    "Source consistency" to R.string.detector_copy_label_source_consistency,
    "Source mismatches" to R.string.detector_copy_label_source_mismatches,
    "Startup preload" to R.string.detector_copy_label_startup_preload,
    "Startup/runtime drift" to R.string.detector_copy_label_startup_runtime_drift,
    "Startup/runtime mount anchor drift" to R.string.detector_copy_label_startup_runtime_mount_anchor_drift,
    "Startup/runtime namespace drift" to R.string.detector_copy_label_startup_runtime_namespace_drift,
    "State" to R.string.detector_copy_label_state,
    "Status" to R.string.detector_copy_label_status,
    "statx cross-check" to R.string.detector_copy_label_statx_cross_check,
    "Strength" to R.string.detector_copy_label_strength,
    "Strong signals" to R.string.detector_copy_label_strong_signals,
    "SU binaries" to R.string.detector_copy_label_su_binaries,
    "SU paths checked" to R.string.detector_copy_label_su_paths_checked,
    "su-related AVC" to R.string.detector_copy_label_su_related_avc,
    "Surface" to R.string.detector_copy_label_surface,
    "Suspicious processes" to R.string.detector_copy_label_suspicious_processes,
    "Synthetic throwable stack" to R.string.detector_copy_label_synthetic_throwable_stack,
    "Syscall pack" to R.string.detector_copy_label_syscall_pack,
    "Syscall pack hits" to R.string.detector_copy_label_syscall_pack_hits,
    "System properties" to R.string.detector_copy_label_system_properties,
    "Telegram reference" to R.string.detector_copy_label_telegram_reference,
    "Temp root artifact" to R.string.detector_copy_label_temp_root_artifact,
    "Temp root CVE exploit artifact" to R.string.detector_copy_label_temp_root_cve_artifact,
    "Thanox runtime IPC" to R.string.detector_copy_label_thanox_runtime_ipc,
    "Throne hunt" to R.string.detector_copy_label_throne_hunt,
    "Throne hunt counters" to R.string.detector_copy_label_throne_hunt_counters,
    "Translated ABI surface" to R.string.detector_copy_label_translated_abi_surface,
    "Translation hits" to R.string.detector_copy_label_translation_hits,
    "Trust root" to R.string.detector_copy_label_trust_root,
    "UID identity" to R.string.detector_copy_label_uid_identity,
    "UID identity hits" to R.string.detector_copy_label_uid_identity_hits,
    "UID name unavailable" to R.string.detector_copy_label_uid_name_unavailable,
    "Unexpected allow" to R.string.detector_copy_label_unexpected_allow,
    "Unexpected process identity" to R.string.detector_copy_label_unexpected_process_identity,
    "Unix sockets" to R.string.detector_copy_label_unix_sockets,
    "USB" to R.string.detector_copy_label_usb,
    "USB runtime" to R.string.detector_copy_label_usb_runtime,
    "VirtualizationService" to R.string.detector_copy_label_virtualization_service,
    "Widevine credential" to R.string.detector_copy_label_widevine_credential,
    "Widevine impact" to R.string.detector_copy_label_widevine_impact,
    "Widevine Java/native parity" to R.string.detector_copy_label_widevine_java_native_parity,
    "Wireless debugging secure-connect" to R.string.detector_copy_label_wireless_debugging_secure_connect,
    "x64 native hook" to R.string.detector_copy_label_x64_native_hook,
    "XposedBridge field" to R.string.detector_copy_label_xposedbridge_field,
    "ZN target list" to R.string.detector_copy_label_zn_target_list,
    "Zygote next mount view" to R.string.detector_copy_label_zygote_next_mount_view,
    "Zygote next namespace observation" to R.string.detector_copy_label_zygote_next_namespace_observation,
    "Critical" to R.string.detector_copy_label_critical,
    "Hooks" to R.string.detector_copy_label_hooks,
    "Identity" to R.string.detector_copy_label_identity,
    "Behavior" to R.string.detector_copy_label_behavior,
    "Boot" to R.string.detector_copy_label_boot,
    "Coverage" to R.string.detector_copy_label_coverage,
    "emojiScan" to R.string.detector_copy_label_emoji_scan,
    "chineseScan" to R.string.detector_copy_label_chinese_scan,
    "scriptScan" to R.string.detector_copy_label_script_scan,
    "telegramScan" to R.string.detector_copy_label_telegram_scan,
    "mentionScan" to R.string.detector_copy_label_mention_scan,
    "customKernel" to R.string.detector_copy_label_custom_kernel,
    "kernelVersionCheck" to R.string.detector_copy_label_kernel_version_check,
    "identityConsistency" to R.string.detector_copy_label_identity_consistency,
    "arm64CpuIdentity" to R.string.detector_copy_label_arm64_cpu_identity,
    "cmdlineCheck" to R.string.detector_copy_label_cmdline_check,
    "cvePatchCheck" to R.string.detector_copy_label_cve_patch_check,
    "kptrRestrict" to R.string.detector_copy_label_kptr_restrict,
    "Brand" to R.string.detector_copy_label_deviceinfo_brand,
    "Manufacturer" to R.string.detector_copy_label_deviceinfo_manufacturer,
    "Model" to R.string.detector_copy_label_deviceinfo_model,
    "Device" to R.string.detector_copy_label_deviceinfo_device,
    "Product" to R.string.detector_copy_label_deviceinfo_product,
    "Board" to R.string.detector_copy_label_deviceinfo_board,
    "Hardware" to R.string.detector_copy_label_deviceinfo_hardware,
    "Bootloader" to R.string.detector_copy_label_deviceinfo_bootloader,
    "Fingerprint" to R.string.detector_copy_label_deviceinfo_fingerprint,
    "Build ID" to R.string.detector_copy_label_deviceinfo_build_id,
    "Incremental" to R.string.detector_copy_label_deviceinfo_incremental,
    "Build type" to R.string.detector_copy_label_deviceinfo_build_type,
    "Tags" to R.string.detector_copy_label_deviceinfo_tags,
    "Build user" to R.string.detector_copy_label_deviceinfo_build_user,
    "Build host" to R.string.detector_copy_label_deviceinfo_build_host,
    "Release" to R.string.detector_copy_label_deviceinfo_release,
    "Codename" to R.string.detector_copy_label_deviceinfo_codename,
    "Security patch" to R.string.detector_copy_label_deviceinfo_security_patch,
    "Preview SDK" to R.string.detector_copy_label_deviceinfo_preview_sdk,
    "Primary ABI" to R.string.detector_copy_label_deviceinfo_primary_abi,
    "ABI list" to R.string.detector_copy_label_deviceinfo_abi_list,
    "32-bit ABIs" to R.string.detector_copy_label_deviceinfo_32_bit_abis,
    "64-bit ABIs" to R.string.detector_copy_label_deviceinfo_64_bit_abis,
    "Kernel" to R.string.detector_copy_label_deviceinfo_kernel,
    "Locale" to R.string.detector_copy_label_deviceinfo_locale,
    "Time zone" to R.string.detector_copy_label_deviceinfo_time_zone,
    "Resolution" to R.string.detector_copy_label_deviceinfo_resolution,
    "Density" to R.string.detector_copy_label_deviceinfo_density,
    "Refresh rate" to R.string.detector_copy_label_deviceinfo_refresh_rate,
    "Verdict" to R.string.detector_copy_label_tee_verdict,
    "Tier" to R.string.detector_copy_label_tee_tier,
    "Trust" to R.string.detector_copy_label_tee_trust,
    "Score" to R.string.detector_copy_label_tee_score,
    "Details" to R.string.detector_copy_label_tee_details,
    "Checks" to R.string.detector_copy_label_tee_checks,
    "Local chain" to R.string.detector_copy_label_tee_local_chain,
    "Chain layout" to R.string.detector_copy_label_tee_chain_layout,
    "Root fingerprint" to R.string.detector_copy_label_tee_root_fingerprint,
    "Versions" to R.string.detector_copy_label_tee_versions,
    "Challenge" to R.string.detector_copy_label_tee_challenge,
    "Verified Boot" to R.string.detector_copy_label_tee_verified_boot,
    "Device IDs" to R.string.detector_copy_label_tee_device_ids,
    "Key properties" to R.string.detector_copy_label_tee_key_properties,
    "User auth" to R.string.detector_copy_label_tee_user_auth,
    "Application" to R.string.detector_copy_label_tee_application,
    "Targets" to R.string.detector_copy_label_dangerousapps_targets,
    "PM" to R.string.detector_copy_label_dangerousapps_pm,
    "Hits" to R.string.detector_copy_label_dangerousapps_hits,
    "Hidden" to R.string.detector_copy_label_dangerousapps_hidden,
    "Inventory" to R.string.detector_copy_label_dangerousapps_inventory,
    "Visible packages" to R.string.detector_copy_label_dangerousapps_visible_packages,
    "Categories" to R.string.detector_copy_label_dangerousapps_categories,
    "Probe families" to R.string.detector_copy_label_dangerousapps_probe_families,
    "Shared storage baseline" to R.string.detector_copy_label_dangerousapps_storage,
    "Scan issues" to R.string.detector_copy_label_dangerousapps_scan_issues,
    "Scan" to R.string.detector_copy_label_dangerousapps_scan,
    "PackageManager" to R.string.detector_copy_label_dangerousapps_packagemanager,
    "Package and behavior probes" to R.string.detector_copy_label_dangerousapps_probe_behavior,
    "Indicators" to R.string.detector_copy_label_tee_indicators,
    "Key pair" to R.string.detector_copy_label_tee_key_pair,
    "Lifecycle" to R.string.detector_copy_label_tee_lifecycle,
    "KeyMint crypto" to R.string.detector_copy_label_tee_keymint_crypto,
    "Timing" to R.string.detector_copy_label_tee_timing,
    "Timing side-channel" to R.string.detector_copy_label_tee_timing_sidechannel,
    "Oversized challenge" to R.string.detector_copy_label_tee_oversized_challenge,
    "ImportKey narrative" to R.string.detector_copy_label_tee_importkey_narrative,
    "KeyMint runtime identity" to R.string.detector_copy_label_tee_keymint_runtime_identity,
    "Cert post-processing" to R.string.detector_copy_label_tee_cert_postprocessing,
    "RKP manufacturer" to R.string.detector_copy_label_tee_rkp_manufacturer,
    "Module hash" to R.string.detector_copy_label_tee_module_hash,
    "Grant isolated-domain" to R.string.detector_copy_label_tee_grant_isolated_domain,
    "Grant caller binding" to R.string.detector_copy_label_tee_grant_caller_binding,
    "Grant access vector" to R.string.detector_copy_label_tee_grant_access_vector,
    "Grant self-domain" to R.string.detector_copy_label_tee_grant_self_domain,
    "Legacy Keystore" to R.string.detector_copy_label_tee_legacy_keystore,
    "Metadata key" to R.string.detector_copy_label_tee_metadata_key,
    "Metadata shape" to R.string.detector_copy_label_tee_metadata_shape,
    "Pure cert" to R.string.detector_copy_label_tee_pure_cert,
    "Pure cert level" to R.string.detector_copy_label_tee_pure_cert_level,
    "Pure cert metadata" to R.string.detector_copy_label_tee_pure_cert_metadata,
    "Operation path" to R.string.detector_copy_label_tee_operation_path,
    "Biometric TEE" to R.string.detector_copy_label_tee_biometric,
    "Binder hook" to R.string.detector_copy_label_tee_binder_hook,
    "Patch mode" to R.string.detector_copy_label_tee_patch_mode,
    "Binder chain" to R.string.detector_copy_label_tee_binder_chain,
    "Update path" to R.string.detector_copy_label_tee_update_path,
    "Update persistence" to R.string.detector_copy_label_tee_update_persistence,
    "Pruning" to R.string.detector_copy_label_tee_pruning,
    "Dual algorithm" to R.string.detector_copy_label_tee_dual_algorithm,
    "ID Attestation" to R.string.detector_copy_label_tee_id_attestation,
    "Broadcast cross-user exception" to R.string.detector_copy_label_hma_broadcast_cross_user,
    "Broadcast final callback completion" to R.string.detector_copy_label_hma_broadcast_completion,
    "Broadcast final result callback" to R.string.detector_copy_label_hma_broadcast_result,
    "Bridge" to R.string.detector_copy_label_lsposed_bridge,
    "getPackageInfo exception" to R.string.detector_copy_label_hma_package_info_exception,
    "getApplicationInfo exception" to R.string.detector_copy_label_hma_application_info_exception,
    "Flags" to R.string.detector_copy_label_nativeroot_flags,
    "getpriority UID visibility" to R.string.detector_copy_label_hma_uid_task_visibility,
    "Seccomp getpriority interference" to R.string.detector_copy_label_hma_seccomp_uid_filter,
    "UID permission visibility (experimental)" to R.string.detector_copy_label_hma_uid_permission_visibility,
    "Caller default network" to R.string.detector_copy_label_network_caller_default,
    "Process binding" to R.string.detector_copy_label_network_process_binding,
    "Visible networks" to R.string.detector_copy_label_network_visible,
    "Default HTTP proxy" to R.string.detector_copy_label_network_default_proxy,
    "JVM HTTP proxy" to R.string.detector_copy_label_network_jvm_proxy,
    "Proxy source cross-check" to R.string.detector_copy_label_network_proxy_crosscheck,
    "Network context" to R.string.detector_copy_label_network_context,
    "Proxy and DNS context" to R.string.detector_copy_label_network_proxy_dns,
    "Client packages" to R.string.detector_copy_label_network_clients,
    "Proxy module coverage" to R.string.detector_copy_label_network_modules,
    "Active tests" to R.string.detector_copy_label_network_active_tests,
    "Sample consistency" to R.string.detector_copy_label_network_sample_consistency,
    "Active protocol / DNS / egress tests" to R.string.detector_copy_label_network_protocol_tests,
    "Routing coverage" to R.string.detector_copy_label_network_routing_coverage,
    "Export privacy" to R.string.detector_copy_label_network_export_privacy,
    "VPN transport" to R.string.detector_copy_label_network_vpn_transport,
    "HTTP proxy" to R.string.detector_copy_label_network_http_proxy,
)

private val detectorCopyValueResources = mapOf(
    "Aligned" to R.string.detector_copy_value_aligned,
    "All zeros" to R.string.detector_copy_value_all_zeros,
    "Allowed" to R.string.detector_copy_value_allowed,
    "API observations differ" to R.string.detector_copy_value_api_observations_differ,
    "Auxiliary DRM signal" to R.string.detector_copy_value_auxiliary_drm_signal,
    "Consistent" to R.string.detector_copy_value_consistent,
    "Corroboration" to R.string.detector_copy_value_corroboration,
    "Coverage unverified" to R.string.detector_copy_value_coverage_unverified,
    "Cross-API mismatch" to R.string.detector_copy_value_cross_api_mismatch,
    "ctime drift" to R.string.detector_copy_value_ctime_drift,
    "Deep" to R.string.detector_copy_value_deep,
    "Digest missing" to R.string.detector_copy_value_digest_missing,
    "Direct" to R.string.detector_copy_value_direct,
    "Guest" to R.string.detector_copy_value_guest,
    "Hook token" to R.string.detector_copy_value_hook_token,
    "Injected" to R.string.detector_copy_value_injected,
    "Installed" to R.string.detector_copy_value_installed,
    "Loaded" to R.string.detector_copy_value_loaded,
    "Lower security session" to R.string.detector_copy_value_lower_security_session,
    "LSPosed ref" to R.string.detector_copy_value_lsposed_ref,
    "Matched" to R.string.detector_copy_value_matched,
    "Denied" to R.string.detector_copy_value_denied,
    "Filtered" to R.string.detector_copy_value_filtered,
    "Full" to R.string.detector_copy_value_full,
    "High" to R.string.detector_copy_value_high,
    "Missing" to R.string.detector_copy_value_missing,
    "Not applicable" to R.string.detector_copy_value_not_applicable,
    "Not observed" to R.string.detector_copy_value_not_observed,
    "Maximum security constrained" to R.string.detector_copy_value_maximum_security_constrained,
    "Mismatch" to R.string.detector_copy_value_mismatch,
    "Mixed" to R.string.detector_copy_value_mixed,
    "Module" to R.string.detector_copy_value_module,
    "Native unavailable" to R.string.detector_copy_value_native_unavailable,
    "No directory events" to R.string.detector_copy_value_no_directory_events,
    "Responded" to R.string.detector_copy_value_responded,
    "Security level unavailable" to R.string.detector_copy_value_security_level_unavailable,
    "Sentinel ID and lower session" to R.string.detector_copy_value_sentinel_id_lower_session,
    "Sentinel system ID" to R.string.detector_copy_value_sentinel_system_id,
    "Sequence drift" to R.string.detector_copy_value_sequence_drift,
    "Session inconclusive" to R.string.detector_copy_value_session_inconclusive,
    "Session level unavailable" to R.string.detector_copy_value_session_level_unavailable,
    "Startup gap" to R.string.detector_copy_value_startup_gap,
    "System ID unavailable" to R.string.detector_copy_value_system_id_unavailable,
    "Watch denied" to R.string.detector_copy_value_watch_denied,
    "Patched" to R.string.detector_copy_value_patched,
    "Unpatched" to R.string.detector_copy_value_unpatched,
    "Partially patched" to R.string.detector_copy_value_partially_patched,
    "Enforcing" to R.string.detector_copy_value_enforcing,
    "Enforcing (paradox)" to R.string.detector_copy_value_enforcing_paradox,
    "Enforcing with KSU context materialized" to R.string.detector_copy_verdict_selinux_enforcing_ksu_context,
    "Strong" to R.string.detector_copy_value_strong,
    "Partially evaluated" to R.string.detector_copy_state_partially_evaluated,
    "Permissive" to R.string.detector_copy_value_permissive,
    "native /proc" to R.string.detector_copy_value_native_proc,
    "fallback file reads" to R.string.detector_copy_value_fallback_file_reads,
    "Tampered" to R.string.detector_copy_value_tampered,
    "Broken" to R.string.detector_copy_value_broken,
    "Review" to R.string.detector_copy_value_review,
    "Scanning" to R.string.detector_copy_value_scanning,
    "Unknown" to R.string.detector_copy_value_unknown,
    "Pending" to R.string.detector_copy_value_pending,
    "Unavailable" to R.string.detector_copy_value_unavailable,
    "Disabled" to R.string.detector_copy_value_disabled,
    "Inconclusive" to R.string.detector_copy_value_inconclusive,
    "No profiles" to R.string.detector_copy_value_no_profiles,
    "None" to R.string.detector_copy_value_none,
    "Software" to R.string.detector_copy_value_software,
    "Factory" to R.string.detector_copy_value_factory,
    "verified" to R.string.detector_copy_value_verified,
    "failed" to R.string.detector_copy_value_failed,
    "Aligned + review" to R.string.detector_copy_value_aligned_review,
    "Not collected" to R.string.detector_copy_value_not_collected,
    "Compatible runtime interface" to R.string.detector_copy_value_runtime_interface,
    "Permission limited" to R.string.detector_copy_value_permission_limited,
    "Permission conflict not observed" to R.string.detector_copy_value_permission_conflict_not_observed,
    "Permission owner observed" to R.string.detector_copy_value_permission_owner_observed,
    "Inconclusive: views differ" to R.string.detector_copy_value_proxy_views_differ,
    "Not comparable: PAC" to R.string.detector_copy_value_proxy_pac,
    "Not comparable: source unavailable" to R.string.detector_copy_value_proxy_unavailable,
    "Observed" to R.string.detector_copy_value_observed,
    "caller default" to R.string.detector_copy_value_network_caller_default,
    "process bound" to R.string.detector_copy_value_network_process_bound,
    "other visible" to R.string.detector_copy_value_network_other_visible,
    "Repeated sample" to R.string.detector_copy_value_network_repeated_sample,
    "Experimental observation" to R.string.detector_copy_value_experimental_observation,
    "Incomplete" to R.string.detector_copy_value_incomplete,
    "Access denied" to R.string.detector_copy_value_access_denied,
    "Evaluation incomplete" to R.string.detector_copy_value_evaluation_incomplete,
    "Package visibility mismatch" to R.string.detector_copy_value_package_visibility_mismatch,
    "Behavior evidence observed" to R.string.detector_copy_value_behavior_evidence,
    "Catalog package presence" to R.string.detector_copy_value_catalog_package_presence,
    "Runtime service presence" to R.string.detector_copy_value_runtime_service_presence,
    "Available evidence only" to R.string.detector_copy_value_available_evidence_only,
    "Consistent in evaluated scope" to R.string.detector_copy_value_hma_consistent,
    "Behavior mismatch observed" to R.string.detector_copy_value_hma_mismatch,
    "Repeated callback timeout (lower confidence)" to R.string.detector_copy_value_hma_timeout,
    "Experimental UID discrepancy observed" to R.string.detector_copy_value_hma_experimental_uid,
    "Offline" to R.string.detector_copy_value_tee_offline,
    "Online" to R.string.detector_copy_value_tee_online,
    "Built-in" to R.string.detector_copy_value_tee_builtin,
    "Revoked" to R.string.detector_copy_value_tee_revoked,
    "Mass abuse" to R.string.detector_copy_value_tee_mass_abuse,
    "Built-in snapshot" to R.string.detector_copy_value_tee_builtin_snapshot,
    "Not included in Attestation" to R.string.detector_copy_value_tee_not_included_attestation,
    "No user auth required" to R.string.detector_copy_value_tee_no_user_auth,
    "Raw app Attestation present" to R.string.detector_copy_value_tee_raw_app_attestation,
    "Skipped" to R.string.detector_copy_value_skipped,
    "Presence with concealed launcher" to R.string.detector_copy_value_presence_concealed_launcher,
    "Manager app presence" to R.string.detector_copy_value_manager_app_presence,
    "Weak anchors only" to R.string.detector_copy_value_weak_anchors_only,
    "No catalog match observed" to R.string.detector_copy_value_no_catalog_match,
    "Coverage incomplete" to R.string.detector_copy_value_coverage_incomplete,
    "Root manager hiding its icon" to R.string.detector_copy_value_root_manager_hidden_icon,
    "Weak root manager match" to R.string.detector_copy_value_weak_root_manager_match,
    "Candidate permission owner observed" to R.string.detector_copy_value_candidate_permission_owner_observed,
    "Launcher enumeration unavailable" to R.string.detector_copy_value_launcher_enumeration_unavailable,
    "Profiles not enumerated" to R.string.detector_copy_value_profiles_not_enumerated,
    "No root manager apps" to R.string.detector_copy_value_no_root_manager_apps,
    "a profile was not observed" to R.string.detector_copy_value_rootmanagers_gap_profile_unobserved,
    "this app was missing from its own launcher list" to R.string.detector_copy_value_rootmanagers_gap_self_missing,
    "package visibility is not full" to R.string.detector_copy_value_rootmanagers_gap_package_visibility,
    "no signing certificate could be read" to R.string.detector_copy_value_rootmanagers_gap_certificate_unreadable,
    "part of the evidence could not be read" to R.string.detector_copy_value_rootmanagers_gap_evidence_unreadable,
    "Root manager visibility" to R.string.detector_copy_value_root_manager_visibility,
    "Searched" to R.string.detector_copy_value_searched,
    "Unsupported platform" to R.string.detector_copy_value_unsupported_platform,
    "Installation authorization required" to R.string.detector_copy_value_installation_authorization_required,
    "Rate limited" to R.string.detector_copy_value_rate_limited,
    "Timed out" to R.string.detector_copy_value_timed_out,
    "Unexpected success; experiment disabled" to R.string.detector_copy_value_unexpected_success_experiment_disabled,
    "high" to R.string.detector_copy_value_high,
    "medium" to R.string.detector_copy_value_medium,
    "low" to R.string.detector_copy_value_low,
    "Root manager apps found" to R.string.detector_copy_value_rootmanagers_apps_found,
    "%1\$d apps checked" to R.string.detector_copy_value_rootmanagers_apps_checked,
    "%1\$d match(es)" to R.string.detector_copy_value_rootmanagers_matches,
    "%1\$d of %2\$d" to R.string.detector_copy_value_count_of_count,
    "%1\$d read · %2\$d failed" to R.string.detector_copy_value_count_read_failed,
    "user %1\$d" to R.string.detector_copy_label_profile_user,
    "class + classloader + bridge fields + callbacks + runtime + logcat + binder + zygote gids + policy + native" to R.string.detector_copy_subtitle_lsposed_loading,
    "local LSPosed/Xposed scan failed" to R.string.detector_copy_subtitle_lsposed_failed,
    "Dirty SELinux policy signal(s)" to R.string.detector_copy_value_lsposed_dirty_policy_signals,
    "KernelSU manager weak fingerprint detected" to R.string.detector_copy_value_nativeroot_kernelsu_manager_weak_fingerprint,
    "One heuristic family needs review" to R.string.detector_copy_value_zygisk_one_heuristic_family_review,
)

private val detectorCopyDetailResources = mapOf(
    "No root indicators" to R.string.detector_copy_verdict_su_no_root_indicators,
    "No root indicators from available probes" to R.string.detector_copy_verdict_su_no_root_indicators_limited,
    "Common su binaries, adb daemons, and native SELinux context probes stayed clean." to R.string.detector_copy_summary_su_clean,
    "Virtualization scan has reduced coverage" to R.string.detector_copy_verdict_virtualization_reduced_coverage,
    "No direct virtualization signal surfaced from the available probes, but one or more native, preload, helper-process, graphics, namespace, or syscall paths were unavailable." to R.string.detector_copy_summary_virtualization_reduced_coverage,
    "LSPosed scan has reduced coverage" to R.string.detector_copy_verdict_lsposed_reduced_coverage,
    "Native root scan has reduced coverage" to R.string.detector_copy_verdict_nativeroot_reduced_coverage,
    "No local contract mismatch observed" to R.string.detector_copy_verdict_locationrisk_no_mismatch,
    "SELinux is enforcing and the visible policy surface looks internally consistent." to R.string.detector_copy_selinux_summary_enforcing_consistent,
    "Permission-denied probes also reinforced the enforcing verdict." to R.string.detector_copy_selinux_summary_paradox,
    "Audit rewrite checks remained non-proving from the current app context." to R.string.detector_copy_selinux_summary_audit_not_proving,
    "The context validity oracle rejected both KSU-specific contexts in live policy." to R.string.detector_copy_selinux_summary_context_rejected,
    "Mandatory access control is active." to R.string.detector_copy_selinux_impact_mac_active,
    "Policy violations should be blocked and logged." to R.string.detector_copy_selinux_impact_violations_blocked,
    "Permission-denied probes acted as positive evidence for enforcing mode." to R.string.detector_copy_selinux_impact_permission_denied,
    "Audit rewrite checks were partially unavailable from this app context." to R.string.detector_copy_selinux_impact_audit_partial,
    "The app_zygote carrier rejected both KSU-specific contexts." to R.string.detector_copy_selinux_impact_context_rejected,
    "Controlled app_zygote attr/current writes did not recognize the tested privileged contexts. A hidden backup policy can produce the same EINVAL results." to R.string.detector_copy_selinux_impact_attr_current_not_recognized,
    "Unlocked state, Attestation contradictions, broken certificate trust, or Verified Boot failures indicate reduced device trust." to R.string.detector_copy_detail_impact_bootloader_unlocked_state,
    "The Android 17 zygote_next native isolated-service path exposed root-managed mount records." to R.string.detector_copy_detail_impact_mount_zygote_root_records,
    "The context validity oracle accepted both KSU-specific contexts from the current carrier." to R.string.detector_copy_detail_selinux_context_accepted,
    "The zygotePreload app_zygote carrier observed a policyload/access seqno split; treat this as KernelSU-specific evidence bounded to the preload carrier." to R.string.detector_copy_detail_selinux_policyload_seqno_split,
    "A trusted DirtySepolicy-style access query reported system_server execmem as allowed." to R.string.detector_copy_detail_selinux_dirty_policy_execmem_allowed,
    "A clean memory slice reduces confidence in in-process runtime hooking only when the native probe ran successfully." to R.string.detector_copy_detail_impact_memory_clean_slice_scope,
    "A clean result lowers confidence in active LSPosed-style hooking for this process, but it does not prove the whole device is stock." to R.string.detector_copy_detail_impact_lsposed_clean_not_whole_device_stock,
    "A clean result reduces confidence in active Zygisk-style tampering for this process, but it does not prove the whole device is stock." to R.string.detector_copy_detail_impact_zygisk_clean_not_stock,
    "A determined ROM can remove obvious signatures, so absence is not proof of stock firmware." to R.string.detector_copy_detail_impact_customrom_absence_not_stock_proof,
    "A direct root token in a visible process mount table is strong evidence of a root-managed mount layer." to R.string.detector_copy_detail_impact_mount_root_token_strong_evidence,
    "A partial CVE patch or exposed kernel pointers can reflect aftermarket hardening gaps rather than active compromise." to R.string.detector_copy_detail_impact_kernel_cve_or_pointer_impact,
    "A root-managed mount remained visible from the Android 17 zygote_next native isolated process." to R.string.detector_copy_detail_impact_mount_root_managed_visible,
    "A same-CPU cached/MIDR_EL1 mismatch indicates that the kernel's cached processor identity was changed independently of its ARM64 register-emulation path." to R.string.detector_copy_detail_impact_kernel_midr_mismatch,
    "Absence of common SU artifacts is not proof that root is impossible." to R.string.detector_copy_detail_impact_su_absence_not_impossible,
    "Absence of residue is not proof of stock state. A determined bypass can clean properties and avoid obvious in-process traces." to R.string.detector_copy_detail_impact_pif_absence_not_stock,
    "Accessible profiles and caller-profile package observations are matched against the manager catalog. Unmatched app identities are excluded from diagnostics." to R.string.detector_copy_detail_diagnostic_rootmanagers_accessible_profiles,
    "Aftermarket firmware can legitimately alter build properties, property storage, bootloader state, privileged services, and security defaults." to R.string.detector_copy_detail_impact_customrom_aftermarket_changes,
    "An inconclusive result is weaker than a warning and can happen when direct Android/data listing behavior does not allow a clean bypass experiment." to R.string.detector_copy_detail_impact_kernel_cve_inconclusive_explanation,
    "Analyzes current-thread and synthetic throwable stacks for XposedBridge, LSPosedBridge, LSPHooker_, and related hook callback tokens." to R.string.detector_copy_detail_method_lsposed_stack_analysis,
    "android.os.SystemProperties reflection reads for tracked boot properties." to R.string.detector_copy_detail_method_bootloader_reflection_reads,
    "android.os.SystemProperties reflection reads." to R.string.detector_copy_detail_method_systemproperties_reflection,
    "androidboot.* values from /proc/cmdline and /proc/bootconfig." to R.string.detector_copy_detail_method_bootloader_raw_params,
    "Attestation behavior, Play Integrity, and some banking or DRM apps may differ on custom ROMs or modified boot chains." to R.string.detector_copy_detail_impact_customrom_attestation_impact,
    "Banking, payment, DRM, and integrity-sensitive apps may refuse to run." to R.string.detector_copy_detail_impact_su_sensitive_apps_impact,
    "Behavior-level signals are weaker than direct naming or boot parameter hits and should be interpreted with device context." to R.string.detector_copy_detail_impact_kernel_behavior_signal_weight,
    "Build.TYPE, Build.TAGS, and Build.FINGERPRINT checks." to R.string.detector_copy_detail_method_systemproperties_build_constants,
    "Builds an off-screen EGL context and inspects GL_VENDOR, GL_RENDERER, and GL_VERSION." to R.string.detector_copy_detail_method_virtualization_egl,
    "Busybox, /data/adb, debug ramdisk payload markers, and hybrid framework path checks." to R.string.detector_copy_detail_method_mount_root_path_markers,
    "Check /proc/kallsyms, /proc/modules, and uname strings for KernelSU, APatch, KernelPatch, SuperCall, or Magisk tokens." to R.string.detector_copy_detail_method_nativeroot_kernel_tokens,
    "Checks ART native bridge properties and translated runtime libraries such as libhoudini, libnb, and libndk_translation." to R.string.detector_copy_detail_method_virtualization_native_bridge,
    "Checks for LSPosed, LSPatch, EdXposed, Xposed installer, TaiChi, VirtualXposed, and common module-manager packages." to R.string.detector_copy_detail_method_lsposed_manager_packages,
    "Checks whether the default uncaught-exception handler class points back to Xposed or LSPosed runtime code." to R.string.detector_copy_detail_method_lsposed_exception_handler,
    "Collecting the cross-process FD trap result and the native runtime snapshot in parallel." to R.string.detector_copy_detail_impact_zygisk_gathering,
    "Collects /proc/self/maps, /proc/self/fd, mountinfo, direct device nodes, and raw mount anchors from the current process." to R.string.detector_copy_detail_method_virtualization_process_maps,
    "Cross-check contradictions mean different system layers disagree about the same boot or build state, which is stronger than a single suspicious value." to R.string.detector_copy_detail_impact_systemproperties_crosscheck_explanation,
    "Cross-source comparison across reflection, getprop, JVM, and native libc reads." to R.string.detector_copy_detail_method_bootloader_cross_source,
    "Detector cards will expand as modules finish collecting local evidence." to R.string.detector_copy_detail_impact_dashboard_cards_expand,
    "Different processes expose different mount tables to the isolated observer, which can indicate selective mount hiding." to R.string.detector_copy_detail_impact_mount_different_views_selective_hiding,
    "Different property APIs returned different values. That can indicate hook-based spoofing, translation issues, or framework/native drift." to R.string.detector_copy_detail_impact_systemproperties_api_mismatch,
    "Direct native hits are stronger than plain package or property signals because they come from syscall behavior, runtime processes, cgroup visibility mismatches, or corroborated runtime residue paths." to R.string.detector_copy_detail_impact_nativeroot_direct_hits_stronger,
    "Direct probes are syscall and side-channel results; indirect probes are kernel strings, paths, processes, properties, and cgroup leakage." to R.string.detector_copy_detail_method_nativeroot_probe_categories,
    "Direct runtime signals come from classes, stack traces, Binder bridges, and native traces; package-only signals are softer residue." to R.string.detector_copy_detail_method_lsposed_evidence_strength,
    "Direct strong signals include FD trap, NeoZygisk TMP_PATH leakage, namespace bypass, linker hook, and TracerPid positives." to R.string.detector_copy_detail_diagnostic_zygisk_direct_strong_signals,
    "FD trap or a direct runtime strong hit is red. One heuristic family is yellow; multiple families escalate to red. Maps and FD loader-path residue count as one family." to R.string.detector_copy_detail_diagnostic_zygisk_state_thresholds,
    "File and adb-daemon probes were clean." to R.string.detector_copy_detail_impact_su_file_adb_clean,
    "Framework-vs-property, fingerprint-tail, raw-boot, and lock-state coherence checks." to R.string.detector_copy_detail_method_systemproperties_coherence,
    "Gathering Attestation, Verified Boot, and property consistency evidence." to R.string.detector_copy_detail_impact_bootloader_gathering,
    "Gathering class, ClassLoader, Binder, runtime-artifact, logcat, package, SELinux policy, and native runtime evidence." to R.string.detector_copy_detail_impact_lsposed_gathering,
    "Gathering current-process guest and translation evidence." to R.string.detector_copy_detail_impact_virtualization_gathering,
    "Gathering local firmware branding and framework evidence." to R.string.detector_copy_detail_impact_customrom_gathering,
    "Gathering local kernel evidence." to R.string.detector_copy_detail_impact_kernel_gathering,
    "Gathering local native root evidence." to R.string.detector_copy_detail_impact_nativeroot_gathering,
    "Gathering local root evidence." to R.string.detector_copy_detail_impact_su_gathering,
    "Gathering local runtime memory evidence." to R.string.detector_copy_detail_impact_memory_gathering,
    "Gathering local status evidence." to R.string.detector_copy_detail_impact_selinux_gathering,
    "Gathering property, boot, and native cross-check evidence." to R.string.detector_copy_detail_impact_systemproperties_gathering,
    "Gathering residue properties and runtime trace evidence for Play Integrity spoof frameworks." to R.string.detector_copy_detail_impact_pif_gathering,
    "Gathering runtime mount and filesystem evidence." to R.string.detector_copy_detail_impact_mount_gathering,
    "Hardened setups can avoid exposing direct stack or class evidence in the current app, so yellow-only results still deserve correlation with other detector cards." to R.string.detector_copy_detail_impact_lsposed_hardened_setup_correlation,
    "Heuristic probes cover solist drift, maps and smaps anomalies, atexit routing, stack residue, suspicious threads or fds, and heap entropy." to R.string.detector_copy_detail_diagnostic_zygisk_heuristic_probes,
    "Hook-like entry changes, deleted executable loaders, or anonymous signal handlers are stronger runtime tampering signals than filesystem-only artifacts." to R.string.detector_copy_detail_impact_memory_direct_runtime_signals,
    "Identity unverified. Permission ownership alone does not establish a root manager." to R.string.detector_copy_detail_diagnostic_rootmanagers_identity_unverified,
    "An app match does not establish root access, current execution or device compromise. Weak anchors and permission ownership alone do not identify a manager. Missing profiles or signing evidence limit absence conclusions." to R.string.detector_copy_detail_rootmanagers_impact_scope,
    "Isolated-process mount drift, manager manifest fingerprints, kernel strings, property residue, or cgroup leakage can indicate native-root history or selective runtime hiding, but they are weaker than direct syscall-side probes." to R.string.detector_copy_detail_impact_nativeroot_indirect_evidence_weaker,
    "JNI-backed maps and heap probes for LSPosed-specific runtime evidence." to R.string.detector_copy_detail_method_lsposed_native_probes,
    "JNI-backed native root detection module." to R.string.detector_copy_detail_method_nativeroot_native_module,
    "Kernel addresses remained hidden during the native probe." to R.string.detector_copy_detail_diagnostic_kernel_addresses_hidden,
    "KernelSU magic prctl probe using option 0xDEADBEEF." to R.string.detector_copy_detail_method_nativeroot_ksu_magic_prctl,
    "Loaded Xposed classes, bridge fields, Binder bridge responses, runtime artifacts, logcat leaks, dirty SELinux policy rules, and native LSPosed keywords are stronger evidence than package residue because they touch the current process, live policy, or system services directly." to R.string.detector_copy_detail_impact_lsposed_direct_evidence_stronger,
    "Manager packages, Xposed module meta-data, or dirty SELinux policy drift show framework or root-policy residue, but they do not prove the current process is hooked right now." to R.string.detector_copy_detail_impact_lsposed_manager_residue_not_active_hook,
    "Memory-map scan for Zygisk, Riru, and Magisk-hidden library paths." to R.string.detector_copy_detail_method_mount_memory_maps,
    "Modified or community-built kernels can change trust posture, boot state, and device integrity behavior." to R.string.detector_copy_detail_impact_kernel_modified_impact,
    "Mountinfo root-field, propagation, mount-ID, and namespace-consistency checks." to R.string.detector_copy_detail_method_mount_mountinfo,
    "Native /proc coverage was unavailable, so pointer exposure could not be verified." to R.string.detector_copy_detail_diagnostic_kernel_proc_unavailable,
    "Native /proc process-context coverage was unavailable on this build." to R.string.detector_copy_detail_impact_su_proc_unavailable,
    "Native coverage was unavailable on this build, so clean native trace results are not available." to R.string.detector_copy_detail_impact_customrom_native_coverage_unavailable,
    "Native framework trace coverage was unavailable on this build." to R.string.detector_copy_detail_diagnostic_customrom_native_framework_unavailable,
    "Native libc property cross-checks using the callback-based system property API." to R.string.detector_copy_detail_method_bootloader_native_libc,
    "Native memory evidence was unavailable, so this support-only result should not be treated as clean." to R.string.detector_copy_detail_impact_memory_native_unavailable,
    "Native SELinux context probes stayed within normal app boundaries." to R.string.detector_copy_detail_impact_su_selinux_context_normal,
    "No common aftermarket firmware branding, property-area, or framework traces were found." to R.string.detector_copy_detail_impact_customrom_no_common_traces,
    "No common KernelSU, APatch, Magisk, SUSFS, or cgroup-leak traces surfaced from the current probe set." to R.string.detector_copy_detail_impact_nativeroot_no_common_traces,
    "No common Play Integrity Fix residue surfaced from the current property catalog or runtime trace heuristics." to R.string.detector_copy_detail_impact_pif_no_common_residue,
    "No common SU binaries or adb root daemons surfaced." to R.string.detector_copy_detail_impact_su_no_common_binaries,
    "No custom ROM signature surfaced from available probes, but package visibility, service, property-area, or native symbol coverage was incomplete." to R.string.detector_copy_detail_impact_customrom_reduced_coverage_explanation,
    "No direct runtime or converging heuristic signal surfaced in the current app process." to R.string.detector_copy_detail_impact_zygisk_no_direct_or_heuristic,
    "No direct virtualization signal surfaced from available probes, but coverage was incomplete." to R.string.detector_copy_detail_impact_virtualization_no_direct_signal,
    "No findings were produced for this section." to R.string.detector_copy_detail_diagnostic_mount_no_findings,
    "No hard kernel naming marker surfaced from fallback identity reads, but native-only /proc checks were unavailable." to R.string.detector_copy_detail_impact_kernel_fallback_no_native,
    "No kernel identity field had two readable sources, so nothing could be cross-checked." to R.string.detector_copy_detail_method_kernelcheck_no_identity_pair,
    "No LSPosed/Xposed signal surfaced from available probes, but one or more runtime evidence paths were unavailable." to R.string.detector_copy_detail_impact_lsposed_no_signal_coverage_incomplete,
    "No native root indicator surfaced from available probes, but one or more support-only evidence paths were unavailable or scoped." to R.string.detector_copy_detail_impact_nativeroot_no_indicator_coverage_incomplete,
    "No Play Integrity Fix residue surfaced from Java-side checks, but native libc and maps coverage was unavailable." to R.string.detector_copy_detail_impact_pif_native_unavailable,
    "No rows were produced for this section on this device." to R.string.detector_copy_detail_diagnostic_bootloader_no_rows,
    "No signal surfaced in this LSPosed evidence slice." to R.string.detector_copy_detail_diagnostic_lsposed_no_signal,
    "No suspicious naming, boot parameter, or behavior signal surfaced." to R.string.detector_copy_detail_impact_kernel_no_suspicious_signals,
    "Observed key properties matched conservative production expectations across multiple read paths." to R.string.detector_copy_detail_impact_systemproperties_multiple_paths_aligned,
    "Observed properties matched conservative expectations, but raw property-area layout coverage was unavailable." to R.string.detector_copy_detail_impact_systemproperties_layout_unavailable,
    "Open detector cards below to review detailed local evidence and secondary checks." to R.string.detector_copy_detail_impact_dashboard_open_cards,
    "Overlayfs support, system filesystem type, and suspicious tmpfs sizing checks." to R.string.detector_copy_detail_method_mount_overlayfs,
    "Persisted spoof properties are relatively strong evidence because they survive process restarts and are readable from multiple layers." to R.string.detector_copy_detail_impact_pif_persisted_properties,
    "Play Integrity, banking apps, or DRM-sensitive apps may react differently on such kernels." to R.string.detector_copy_detail_impact_kernel_play_integrity_impact,
    "Privilege-escalation tooling is present or visible from this app context." to R.string.detector_copy_detail_impact_su_privilege_tools_present,
    "Probes activity and serial Binder services for LSPosed bridge transaction behavior and descriptors." to R.string.detector_copy_detail_method_lsposed_binder_services,
    "Raw /dev/__properties__ hole residue means the property storage layout no longer matches a normal append-only allocation pattern." to R.string.detector_copy_detail_impact_systemproperties_raw_hole_residue,
    "Raw-boot, lock-state, partition-verity, and build-profile coherence checks." to R.string.detector_copy_detail_method_bootloader_coherence,
    "Read a small catalog of root-specific properties such as ro.kernel.ksu and APatch/KernelPatch variants." to R.string.detector_copy_detail_method_nativeroot_root_properties,
    "Read the individual findings together with Memory and Mount; runtime residue can also have legitimate causes." to R.string.detector_copy_detail_impact_zygisk_correlate_memory_mount,
    "Read this together with Memory and Mount, which can still surface loader and mapping residue in parallel." to R.string.detector_copy_detail_impact_zygisk_correlate_loader_mapping,
    "Reflects XposedBridge.disableHooks and XposedBridge.sHookedMethodCallbacks to confirm live bridge state rather than class residue alone." to R.string.detector_copy_detail_method_lsposed_bridge_state,
    "Repeated file-object growth correlates with wrapper reopens. Review this as a leak indicator; global file activity can confound the result, and fixed KernelSU builds do not have this leak." to R.string.detector_copy_detail_impact_nativeroot_file_object_growth,
    "Repeated prctl timing is supporting evidence only. Scheduling, virtualization and unrelated security hooks can produce similar effects; this is not a KernelSU or root identification." to R.string.detector_copy_detail_impact_nativeroot_prctl_timing_support_only,
    "Reports returned statx mount-ID and mount-root fields. Missing fields or syscall errors limit coverage; non-atomic differences do not establish tampering." to R.string.detector_copy_detail_method_mount_statx,
    "Resolve known Xposed, libXposed, and LSPosed runtime classes through boot and app-facing class loaders." to R.string.detector_copy_detail_method_lsposed_class_resolution,
    "Review findings often come from mapping hygiene, loader visibility, or vDSO consistency rather than a direct redirection primitive." to R.string.detector_copy_detail_impact_memory_review_mapping_hygiene,
    "Root managers can hide files, alter system behavior, and weaken app trust signals." to R.string.detector_copy_detail_impact_su_root_manager_impact,
    "Runtime mount table scan for Magisk paths, writable system partitions, overlays, loop devices, and observed source paths." to R.string.detector_copy_detail_method_mount_runtime_table,
    "Runtime traces in current-process maps can indicate bypass code, deleted artifacts, or keystore-adjacent tampering still touching the app process." to R.string.detector_copy_detail_impact_pif_runtime_traces,
    "Samples readable Dalvik heap regions through /proc/self/mem for LSPosed and Xposed keyword residuals." to R.string.detector_copy_detail_method_lsposed_dalvik_heap,
    "Scans /data/local/tmp for temp root exploit artifacts (ksud, temp_su, ksu-helper, ksu-payload, libcve43499root.so). Files matching the CVE-2026-43499 tooling show it was staged on this device; they do not show whether an escalation succeeded or is still active. Paths this process cannot stat leave the check unavailable." to R.string.detector_copy_detail_method_nativeroot_temp_root_artifacts,
    "Scans /proc/self/maps for LSPosed, XposedBridge, libXposed, LSPlant, EdXposed, and LSPatch runtime mappings." to R.string.detector_copy_detail_method_lsposed_proc_maps,
    "Scans installed app manifest meta-data such as xposedmodule, xposedminversion, and xposedscope." to R.string.detector_copy_detail_method_lsposed_module_metadata,
    "Signing fingerprints provide catalog identity anchors; unreadable certificates reduce coverage." to R.string.detector_copy_detail_diagnostic_rootmanagers_signing_fingerprints,
    "Single getprop dump parsed once and reused for cross-checks." to R.string.detector_copy_detail_method_systemproperties_getprop,
    "Single getprop dump reused for cross-source comparisons." to R.string.detector_copy_detail_method_bootloader_getprop_dump,
    "Source mismatches mean property APIs disagree. That often points to hook-based translation, cleanup drift, or framework/native divergence." to R.string.detector_copy_detail_impact_pif_source_mismatch,
    "System properties are still software-readable values, so even aligned results should be combined with kernel, SU, TEE, and package-level signals." to R.string.detector_copy_detail_impact_systemproperties_software_readable_caveat,
    "System.getProperty fallback reads." to R.string.detector_copy_detail_method_systemproperties_jvm,
    "The current app process did not expose LSPosed/Xposed class loading, Binder bridge behavior, or LSPosed-native runtime strings." to R.string.detector_copy_detail_impact_lsposed_no_current_process_evidence,
    "The current process did not expose branch-heavy function entries, suspicious executable memfd paths, or loader visibility mismatches." to R.string.detector_copy_detail_impact_memory_no_direct_runtime_evidence,
    "The CVE-2024-43093 probe suggests the path-filter fix is missing or incomplete, but this remains informational context rather than a root or tamper verdict." to R.string.detector_copy_detail_impact_kernel_cve_fix_missing,
    "The CVE-2024-43093 probe was inconclusive, so this card cannot claim the path-filter fix is present." to R.string.detector_copy_detail_impact_kernel_cve_inconclusive,
    "The detector completed, but at least one major path was unavailable, so this result is support-only rather than clean." to R.string.detector_copy_detail_impact_zygisk_support_only,
    "The findings here are weaker than a direct hook or deleted loader hit, but they still mean the runtime view is not fully boring." to R.string.detector_copy_detail_impact_memory_weaker_findings,
    "The kernel identity differs between the sources that export it, so the version this device reports to apps is being rewritten rather than simply being unusual." to R.string.detector_copy_detail_impact_kernel_identity_rewritten,
    "The optional timing experiment found a repeatable delay relative to both controls. Background fsnotify readers and scheduling remain possible causes; this does not identify a root solution." to R.string.detector_copy_detail_impact_nativeroot_timing_experiment,
    "The sacrificial reboot() helper died under app seccomp before it could install a temporary [ksu_driver] fd. Other KernelSU checks still ran." to R.string.detector_copy_detail_diagnostic_nativeroot_seccomp_reboot_helper,
    "These heuristics do not prove malicious compromise, but they do indicate the kernel differs from conservative stock expectations." to R.string.detector_copy_detail_impact_kernel_heuristics_not_compromise,
    "These packages were detected by direct corroboration probes but hidden from PackageManager inventory. This is the only Dangerous Apps path that stays red." to R.string.detector_copy_detail_diagnostic_dangerousapps_hidden_inventory,
    "This card only sees the current app process, so it should be read together with mount, SU, kernel, and TEE evidence." to R.string.detector_copy_detail_impact_memory_current_process_scope,
    "This card still observes only a narrow runtime slice. Read it together with Memory, Native Root, Mount, and System Properties when the setup is actively hiding itself." to R.string.detector_copy_detail_impact_lsposed_narrow_runtime_slice,
    "This LSPosed evidence slice was unavailable or scoped, so it is not treated as clean." to R.string.detector_copy_detail_diagnostic_lsposed_evidence_unavailable,
    "This remains heuristic evidence rather than proof of a fully stock device." to R.string.detector_copy_detail_impact_kernel_heuristic_not_stock_proof,
    "This remains heuristic evidence, not proof of an unmodified device." to R.string.detector_copy_detail_impact_su_heuristic_not_proof,
    "This signal alone does not prove malicious compromise or active root access." to R.string.detector_copy_detail_impact_customrom_signal_not_proof,
    "This signal is useful for hardening posture, but it should not elevate the entire kernel card to warning on its own." to R.string.detector_copy_detail_impact_kernel_signal_not_card_warning,
    "This support-only result has reduced coverage and should not be read as a strong clean kernel verdict." to R.string.detector_copy_detail_impact_kernel_support_only_reduced,
    "This support-only result lowers confidence only for the probes that actually ran." to R.string.detector_copy_detail_impact_lsposed_support_only_confidence,
    "Tracked boot, AVB, dm-verity, Samsung fuse, and secure-build properties." to R.string.detector_copy_detail_method_bootloader_tracked_properties,
    "Transparent NativeActivity launcher runs early namespace and mount checks before MainActivity starts." to R.string.detector_copy_detail_method_mount_early_launcher,
    "Unattributed directory activity; diagnostic only." to R.string.detector_copy_detail_diagnostic_nativeroot_unattributed_directory_activity,
    "Unavailable helper or native paths reduce confidence without implying a positive detection." to R.string.detector_copy_detail_impact_virtualization_unavailable_paths,
    "Unavailable service binding, an unsupported heap helper, or a missing native snapshot can all reduce confidence without implying a positive detection." to R.string.detector_copy_detail_impact_zygisk_unavailable_paths,
    "User IDs 0–999 searched. Mount namespaces and access restrictions can hide existing directories." to R.string.detector_copy_detail_diagnostic_rootmanagers_user_ids_searched,
    "Visible payload names provide additional manager anchors; inaccessible directories remain unknown." to R.string.detector_copy_detail_diagnostic_rootmanagers_visible_payloads,
    "Walks app-facing ClassLoader parent chains and flags loader names or chain depth that resemble LSPosed/Xposed injection." to R.string.detector_copy_detail_method_lsposed_classloader_chain,
    "Yellow means only weaker corroboration traces were found, not a single decisive runtime primitive on their own." to R.string.detector_copy_detail_impact_zygisk_yellow_heuristics,
    "No hook-like memory signals" to R.string.detector_copy_detail_memory_no_hook_signals,
    "No hook-style prologue changes, suspicious executable memfd paths, or loader visibility mismatches surfaced." to R.string.detector_copy_detail_memory_no_hook_artifacts,
    "No Play Integrity residue surfaced" to R.string.detector_copy_detail_play_integrity_no_residue,
    "multi-source props + native libc + runtime maps" to R.string.detector_copy_subtitle_playintegrityfix_loading,
    "local Play Integrity residue scan failed" to R.string.detector_copy_subtitle_playintegrityfix_failed,
    "Scanning Play Integrity residue" to R.string.detector_copy_detail_playintegrityfix_scanning,
    "Play Integrity Fix scan failed" to R.string.detector_copy_detail_playintegrityfix_failed,
    "Play Integrity scan has reduced native coverage" to R.string.detector_copy_detail_playintegrityfix_native_reduced,
    "Property residue, cross-source drift, and current-process runtime traces are being collected from Java and native probes." to R.string.detector_copy_detail_playintegrityfix_collecting,
    "Play Integrity Fix scan failed before evidence could be assembled." to R.string.detector_copy_detail_playintegrityfix_failed_before_evidence,
    "Direct spoof properties or runtime traces suggest active or recently used Play Integrity bypass infrastructure." to R.string.detector_copy_detail_playintegrityfix_direct,
    "Only lower-confidence residue or cross-source drift surfaced. This can reflect disabled leftovers, partial cleanup, or source disagreement." to R.string.detector_copy_detail_playintegrityfix_review,
    "No catalogued Play Integrity residue property or runtime trace was observed across reflection, getprop, native libc, and maps checks." to R.string.detector_copy_detail_playintegrityfix_clean_summary,
    "Java-side checks were clean, but native property and runtime trace coverage was unavailable on this build." to R.string.detector_copy_detail_playintegrityfix_native_unavailable,
    "No target trace was observed in this snapshot. GC, USAP, native fork paths and other zygote instances can hide traces; startup history is incomplete." to R.string.detector_copy_detail_heap_no_target_trace,
    "No Zygisk runtime signal" to R.string.detector_copy_detail_zygisk_no_signal,
    "Device profile collected" to R.string.detector_copy_detail_deviceinfo_profile_collected,
    "No suspicious kernel markers" to R.string.detector_copy_detail_kernel_no_markers,
    "No hard kernel naming or boot-time anomaly surfaced." to R.string.detector_copy_detail_kernel_no_hard_anomaly,
    "Kernel identity, boot parameters, and behavior heuristics stayed within expected bounds." to R.string.detector_copy_detail_kernel_identity_clean,
    "ZWC is blocked, but at least one other ignorable codepoint still bypasses the path filter." to R.string.detector_copy_detail_kernel_zwc_partial,
    "Unicode ignorable codepoints still bypass the path filter." to R.string.detector_copy_detail_kernel_zwc_unpatched,
    "Requires Android 17" to R.string.detector_copy_detail_mount_requires_android17,
    "Reading /proc/1/ns/mnt is normally blocked for unprivileged apps, so namespace comparison coverage is partial." to R.string.detector_copy_detail_mount_namespace_coverage,
    "App data reports the VFS mount-root attribute; this is not an integrity violation." to R.string.detector_copy_detail_mount_vfs_root,
    "Review the listed mount properties in the context of this device and build; a warning alone does not establish root." to R.string.detector_copy_detail_mount_review_properties,
    "Permission-restricted paths and namespace boundaries can hide part of the mount picture, so combine this card with SU, TEE, kernel, and package detectors." to R.string.detector_copy_detail_mount_permission_restricted,
    "The mount layer is not obviously compromised, but it still contains review-worthy runtime or filesystem drift." to R.string.detector_copy_detail_mount_layer_review,
    "Scanning boot state and Verified Boot evidence" to R.string.detector_copy_card_bootloader_scanning,
    "Bootloader scan failed before evidence could be assembled." to R.string.detector_copy_card_bootloader_failed,
    "The boot chain is not obviously broken, but custom-root, software-only, Widevine DRM, or cross-source coherence signals still need review." to R.string.detector_copy_card_bootloader_review,
    "Boot properties look conservative, but the result falls back to software-readable signals because Attestation RootOfTrust was unavailable." to R.string.detector_copy_card_bootloader_fallback,
    "Neither Attestation RootOfTrust nor readable boot properties exposed enough data for a confident bootloader verdict." to R.string.detector_copy_card_bootloader_inconclusive,
    "No unlock or integrity contradiction was observed in the available boot evidence. Individual checks show comparison coverage." to R.string.detector_copy_card_bootloader_clean,
    "Scanning aftermarket firmware signals" to R.string.detector_copy_card_customrom_scanning,
    "System properties, prop integrity, runtime packages/services, framework traces, and resource map checks are collecting local firmware evidence." to R.string.detector_copy_card_customrom_collecting,
    "Custom ROM scan failed before evidence could be assembled." to R.string.detector_copy_card_customrom_failed,
    "Build properties, property-area integrity, bootloader state, runtime packages or services, framework traces, native symbol traces, or resource map anomalies indicate aftermarket firmware, resetprop-style changes, or an unlocked boot chain." to R.string.detector_copy_card_customrom_detection,
    "Native coverage was unavailable on this build, so only Java-side probes were used." to R.string.detector_copy_card_customrom_native_unavailable,
    "No common custom ROM branding, property-area, service, package, framework trace, native symbol trace, or resource map anomaly surfaced from local probes." to R.string.detector_copy_card_customrom_clean,
    "Scanning root artifacts" to R.string.detector_copy_card_su_scanning,
    "File, PATH, adb-daemon, SELinux context, and /proc visibility probes are collecting local evidence." to R.string.detector_copy_card_su_collecting,
    "SU scan failed before root evidence could be assembled." to R.string.detector_copy_card_su_failed,
    "SELinux context probes surfaced abnormal app labels or corroborating root-like process-context residue." to R.string.detector_copy_card_su_context,
    "Common su binaries were found in system or adb-managed locations." to R.string.detector_copy_card_su_binaries,
    "File and daemon probes were clean, but JNI-backed /proc process enumeration was unavailable." to R.string.detector_copy_card_su_proc_unavailable,
    "Scanning property, boot, and source state" to R.string.detector_copy_card_sysprops_scanning,
    "System property scan failed before evidence could be assembled." to R.string.detector_copy_card_sysprops_failed,
    "Property values, raw boot contradictions, cross-source drift, cross-check drift, or raw property-area residue indicate insecure build state, spoofing risk, or modified boot context." to R.string.detector_copy_card_sysprops_detection,
    "Cross-source drift, cross-property drift, or raw property-area residue suggests a review-worthy build or boot context, even if not every warning means active compromise." to R.string.detector_copy_card_sysprops_review,
    "No risky property or coherence drift surfaced from available probes, but raw property-area layout coverage was unavailable." to R.string.detector_copy_card_sysprops_native_unavailable,
    "Key properties, framework constants, native libc reads, raw boot parameters, and property-area layout stayed aligned." to R.string.detector_copy_card_sysprops_clean,
    "Scanning virtualization and translation state" to R.string.detector_copy_card_virtualization_scanning,
    "Virtualization scan failed before evidence could be assembled." to R.string.detector_copy_card_virtualization_failed,
    "The current app context contains direct emulator, AVF guest, device-node, classpath, UID, or runtime-service evidence." to R.string.detector_copy_card_virtualization_direct,
    "The app is not conclusively inside a guest, but translation, renderer, classpath drift, consistency drift, or honeypot anomalies still require review." to R.string.detector_copy_card_virtualization_review,
    "Known virtualization host apps are present on the device, but current process probes did not confirm guest execution." to R.string.detector_copy_card_virtualization_hosts,
    "No direct emulator, AVF guest, native-bridge, or cross-process drift artifact surfaced from the current app context." to R.string.detector_copy_card_virtualization_clean,
    "Scanning Zygisk runtime traces" to R.string.detector_copy_card_zygisk_scanning,
    "Zygisk detection failed before evidence could be assembled." to R.string.detector_copy_card_zygisk_failed,
    "FD trap or direct runtime probes exposed evidence consistent with TMP_PATH leakage, specialization tampering, namespace bypass, linker redirection, ptrace attachment, or libc-hook side effects." to R.string.detector_copy_card_zygisk_direct,
    "Multiple heuristic families surfaced in the current process. Review the individual findings and benign causes; these observations do not establish Zygisk injection." to R.string.detector_copy_card_zygisk_heuristic,
    "Only heuristic residue surfaced, so this result should be read together with Memory and Mount before treating it as a confirmed Zygisk runtime." to R.string.detector_copy_card_zygisk_residue,
    "The FD trap stayed clean and the native runtime snapshot did not expose TMP_PATH, linker, maps, heap, thread, or descriptor traces associated with Zygisk-style injection." to R.string.detector_copy_card_zygisk_clean,
    "One or more major scan paths were unavailable, so this card cannot treat the absence of hits as a clean runtime result." to R.string.detector_copy_card_zygisk_unavailable,
    "Correlating Android debugging settings, USB runtime, properties and wireless ADB discovery." to R.string.detector_copy_card_adb_collecting,
    "The scan failed before it collected evidence." to R.string.detector_copy_card_adb_failed,
    "No ADB state source was observable from this app process." to R.string.detector_copy_card_adb_unavailable,
    "No completed runtime conclusion is available." to R.string.detector_copy_card_adb_inconclusive,
    "An ADB runtime surface disagrees with the init lifecycle. This does not identify a root or hiding implementation." to R.string.detector_copy_card_adb_mismatch,
    "Debugging settings or runtime activity were observed. ADB can be enabled on an ordinary device and does not establish root access." to R.string.detector_copy_card_adb_enabled,
    "Only available sources were evaluated. Permission restrictions, discovery failures and lifecycle transitions limit negative observations." to R.string.detector_copy_card_adb_limited,
    "Cross-check debugging state across independent Android subsystems" to R.string.detector_copy_card_adb_crosscheck,
    "Scanning LSPosed/Xposed runtime and residue" to R.string.detector_copy_card_lsposed_scanning,
    "LSPosed detection failed before evidence could be assembled." to R.string.detector_copy_card_lsposed_failed,
    "Binder bridge replies, loaded Xposed classes, XposedBridge fields, callback handlers, runtime artifacts, logcat leaks, zygote permission GID mismatches, dirty SELinux policy rules, stack trace signatures, or native LSPosed keywords point to active hook-framework presence rather than passive install residue." to R.string.detector_copy_card_lsposed_direct,
    "Installed managers, deep ClassLoader chains, environment residue, dirty SELinux policy drift, or pattern-only logcat traces were found, but the current process did not expose enough stronger runtime evidence to treat the framework as confirmed active here." to R.string.detector_copy_card_lsposed_manager_residue,
    "No LSPosed/Xposed signal surfaced from the available probes, but at least one runtime, package, logcat, or native evidence path was unavailable." to R.string.detector_copy_card_lsposed_limited,
    "No Xposed class loading, ClassLoader, callback, Binder bridge, runtime artifact, logcat, stack, maps, or heap traces surfaced in the current app process." to R.string.detector_copy_card_lsposed_clean,
    "Scanning kernel-root indicators" to R.string.detector_copy_card_nativeroot_scanning,
    "Native Root scan failed before evidence could be assembled." to R.string.detector_copy_card_nativeroot_failed,
    "Read-only ksu_driver hits, direct syscall hits, self-process IOC, root-manager paths, curated runtime residue paths, /data/local/tmp metadata drift, cgroup/process leakage, unexpected root processes, or isolated-process namespace drift indicate active native root infrastructure." to R.string.detector_copy_card_nativeroot_direct,
    "Only weaker isolated-process mount drift, cross-process mount view divergence, manager manifest fingerprints, supporting syscall timing, process, cgroup, kernel, property, or metadata residue surfaced. These are review-worthy, but not as strong as direct native probes." to R.string.detector_copy_card_nativeroot_weaker,
    "This detector relies mostly on JNI-backed native probes. Native coverage was unavailable on this build, and the remaining runtime checks stayed clean." to R.string.detector_copy_card_nativeroot_unavailable,
    "No native root indicator surfaced from available probes, but one or more direct, cgroup, isolated-process, or package-visibility evidence paths had reduced coverage." to R.string.detector_copy_card_nativeroot_limited,
    "Checking installed apps across the accessible profiles." to R.string.detector_copy_card_rootmanagers_checking,
    "The scan failed before the enumeration ran." to R.string.detector_copy_card_rootmanagers_failed,
    "This is a permission-name anchor; manager identity, profile and root access are not established by it." to R.string.detector_copy_card_rootmanagers_permission_anchor,
    "Only weak anchors matched, so these apps are informational, never warnings." to R.string.detector_copy_card_rootmanagers_weak,
    "The launcher enumeration was unavailable, so the absence of matches says nothing." to R.string.detector_copy_card_rootmanagers_launcher_unavailable,
    "No profile could be enumerated, so the absence of matches says nothing." to R.string.detector_copy_card_rootmanagers_profiles_unavailable,
    "A match is evidence an app is installed, not proof that the device is rooted." to R.string.detector_copy_card_rootmanagers_match_not_rooted,
    "Warnings highlight local contract mismatches, cached mock marks or the reference package. Cached marks can be historical or legitimate tests; package identity is unverified and installation does not establish activity. No check authenticates the real position." to R.string.detector_copy_card_locationrisk_warning,
    "Four contracts share one framework surface; they are not independent trust sources." to R.string.detector_copy_card_locationrisk_contracts,
    "Historical cached fixes only; false does not authenticate a position." to R.string.detector_copy_card_locationrisk_cached,
    "Exact package name; identity unverified; installation does not establish activity." to R.string.detector_copy_card_locationrisk_reference,
    "Opt-in, foreground permission, up to three cached reads; no sensor request." to R.string.detector_copy_card_locationrisk_cache_access,
    "Public setMock requires API 31; older releases are unsupported." to R.string.detector_copy_card_locationrisk_setmock,
    "System-service-only spoofing, selective hooks, an excluded app or coherent forged metadata can pass local checks. No GNSS, Wi-Fi, cell, IP or trajectory cross-validation; no module attribution." to R.string.detector_copy_card_locationrisk_boundary,
    "Capturing a fresh isolated-process heap." to R.string.detector_copy_card_heap_scanning,
    "The isolated heap probe failed before evaluation completed." to R.string.detector_copy_card_heap_failed,
    "No snapshot evaluation has completed. Historical coverage is unknown." to R.string.detector_copy_card_heap_no_snapshot,
    "This release predates the audited Android 12 to 17 baselines and is unsupported." to R.string.detector_copy_card_heap_unsupported,
    "The isolated heap probe was unavailable. No absence conclusion is possible." to R.string.detector_copy_card_heap_unavailable,
    "The snapshot could not establish usable startup argument evidence. Coverage is unknown." to R.string.detector_copy_card_heap_snapshot_unknown,
    "Scanning runtime memory" to R.string.detector_copy_card_memory_scanning,
    "Memory detection failed before native evidence could be assembled." to R.string.detector_copy_card_memory_failed,
    "High-risk findings point to hook-like code redirection, suspicious executable mappings, or loader-visible runtime artifacts." to R.string.detector_copy_card_memory_highrisk,
    "Native memory evidence was unavailable, so this card cannot treat the absence of findings as a clean runtime result." to R.string.detector_copy_card_memory_native_unavailable,
    "Grant self-domain key visibility diverged; open TEE details for stage diagnostics." to R.string.detector_copy_card_tee_grant_self_key,
    "Grant self-domain certificate chain diverged; open TEE details for stage diagnostics." to R.string.detector_copy_card_tee_grant_self_chain,
    "Grant isolated-domain key visibility diverged; open TEE details for stage diagnostics." to R.string.detector_copy_card_tee_isolated_key,
    "Grant isolated-domain runtime crash; open TEE details for stage diagnostics." to R.string.detector_copy_card_tee_isolated_crash,
    "Grant isolated-domain certificate chain diverged; open TEE details for stage diagnostics." to R.string.detector_copy_card_tee_isolated_chain,
    "Grant handle caller binding failed; open TEE details for stage diagnostics." to R.string.detector_copy_card_tee_caller_binding,
    "Runtime and Attestation patch levels line up locally." to R.string.detector_copy_detail_tee_patch_matched,
    "Patch levels drift slightly but stay within a short window." to R.string.detector_copy_detail_tee_patch_warning,
    "Runtime and Attestation patch levels drift by more than three months." to R.string.detector_copy_detail_tee_patch_suspicious,
    "Patch comparison was unavailable." to R.string.detector_copy_detail_tee_patch_unknown,
    "Attestation and Keymaster versions violate the AOSP single-runtime mapping." to R.string.detector_copy_detail_tee_keymaster_mapping,
    "VINTF KeyMint version diverged from Attestation." to R.string.detector_copy_detail_tee_vintf_diverged,
    "Grant isolated-domain certificate-chain narrative split detected." to R.string.detector_copy_detail_tee_grant_isolated_chain,
    "Grant isolated-domain key visibility divergence detected." to R.string.detector_copy_detail_tee_grant_isolated_key,
    "Grant isolated-domain isolated private readback crashed after grant succeeded." to R.string.detector_copy_detail_tee_grant_isolated_crash,
    "Grant handle remained readable by its non-grantee owner." to R.string.detector_copy_detail_tee_grant_owner_readable,
    "Domain.GRANT handle without GET_INFO still allowed getKeyEntry metadata readback." to R.string.detector_copy_detail_tee_grant_getinfo,
    "Grant self-domain certificate-chain split detected." to R.string.detector_copy_detail_tee_grant_self_chain,
    "Grant self-domain key visibility divergence detected." to R.string.detector_copy_detail_tee_grant_self_key,
    "Grant self-domain custom Attestation visibility divergence detected." to R.string.detector_copy_detail_tee_grant_self_custom,
    "Leaf certificate key did not verify fresh local signatures." to R.string.detector_copy_detail_tee_leaf_signatures,
    "AndroidKeyStore AES-GCM round-trip failed." to R.string.detector_copy_detail_tee_aes_gcm,
    "AndroidKeyStore AES-GCM key was software-backed instead of secure hardware." to R.string.detector_copy_detail_tee_aes_software,
    "Delete/regenerate behavior contradicted a clean keystore path." to R.string.detector_copy_detail_tee_keystore_regen,
    "getKey() returned a key object for a certificate-only entry." to R.string.detector_copy_detail_tee_cert_only_key,
    "Certificate-only entry exposed Keystore2 security-level metadata." to R.string.detector_copy_detail_tee_cert_keystore2,
    "Keystore2 operation error handling diverged from checks keystore2 itself enforces." to R.string.detector_copy_detail_tee_keystore2_errors,
    "Strong biometric was available, but user-auth-bound key creation or retrieval failed." to R.string.detector_copy_detail_tee_biometric_auth,
    "generateKey and getKeyEntry returned different certificate materials." to R.string.detector_copy_detail_tee_cert_material_diff,
    "Java KeyStore, generateKey, and getKeyEntry certificate materials diverged." to R.string.detector_copy_detail_tee_cert_material_threeway,
    "Primary TrickyStore DER fingerprint matched locally." to R.string.detector_copy_detail_tee_trickystore_der,
    "A library mapped into this process matched TrickyStore's name." to R.string.detector_copy_detail_tee_trickystore_mapping,
    "Native process-side probes did not run" to R.string.detector_copy_detail_tee_native_unavailable,
    "Soter check skipped" to R.string.detector_copy_detail_tee_soter_skipped,
    "Attestation and trust-path checks still aligned." to R.string.detector_copy_detail_tee_attestation_aligned_tail,
    "No certificate chain available for revocation checks." to R.string.detector_copy_detail_tee_crl_no_chain,
    "Built-in revocation snapshot is active; online refresh is awaiting startup consent." to R.string.detector_copy_detail_tee_crl_consent,
    "Built-in revocation snapshot is active; online refresh is disabled in Settings." to R.string.detector_copy_detail_tee_crl_disabled,
    "Online revocation data refreshed successfully." to R.string.detector_copy_detail_tee_crl_refreshed,
    "Online CRL refresh failed; built-in revocation snapshot was used." to R.string.detector_copy_detail_tee_crl_failed,
    "Scanning SELinux state" to R.string.detector_copy_card_selinux_scanning,
    "SELinux scan failed before the detector could assemble local evidence." to R.string.detector_copy_card_selinux_failed,
    "Checking sysfs, getenforce, /proc/self/attr/current, and app_zygote attr writes before deriving final mode with paradox logic." to R.string.detector_copy_card_selinux_collecting,
    "SELinux is enforcing, but the policy looks severely weakened or modified." to R.string.detector_copy_card_selinux_policy_weakened,
    "SELinux is enforcing, but policy analysis found noticeable drift." to R.string.detector_copy_card_selinux_policy_drift,
    "SELinux is enforcing and only minor policy drift surfaced." to R.string.detector_copy_card_selinux_minor_drift,
    "SELinux is enforcing, but the SID-table experiment did not match stock registration behavior." to R.string.detector_copy_card_selinux_sidtab_mismatch,
    "A strong, repeatable ordinary-app attr/current timing asymmetry was observed; attribution remains device-dependent." to R.string.detector_copy_card_selinux_timing,
    "Recent audit or log markers suggest logd output is being rewritten before apps inspect it." to R.string.detector_copy_card_selinux_audit_rewrite,
    "Recent audit evidence exposed readable SELinux AVC denial lines, which indicates audit side-channel leakage rather than direct root-process proof." to R.string.detector_copy_card_selinux_audit_leak,
    "Readable auditpatch residue suggests the audit surface may be rewritten." to R.string.detector_copy_card_selinux_auditpatch,
    "The context validity oracle repeated inconsistently, so its KSU verdict was not trusted." to R.string.detector_copy_card_selinux_context_repeat,
    "The context validity oracle failed its self-test, so its KSU verdict was not trusted." to R.string.detector_copy_card_selinux_context_selftest,
    "The context validity oracle split across the two KSU-specific contexts." to R.string.detector_copy_card_selinux_context_split,
    "The dedicated app_zygote carrier did not land in the expected app_zygote context, so app_zygote-only SELinux evidence was not trusted." to R.string.detector_copy_card_selinux_carrier_context,
    "WARNING: The dedicated app_zygote carrier failed to start or connect, so its SELinux preload checks did not complete. This is a detection-environment failure, not proof of policy tampering." to R.string.detector_copy_card_selinux_carrier_startup,
    "The context validity oracle stayed unavailable." to R.string.detector_copy_card_selinux_context_unavailable,
    "SELinux still labels activity, but violations are logged instead of blocked." to R.string.detector_copy_card_selinux_logged_only,
    "Mandatory access control is off, so SELinux no longer constrains process behavior." to R.string.detector_copy_card_selinux_mac_off,
    "Local probes did not resolve a stable SELinux mode." to R.string.detector_copy_card_selinux_unresolved,
    "Audit logs appear rewritten, so SELinux denials may look normal even when privileged contexts are present." to R.string.detector_copy_card_selinux_audit_impact,
    "Readable SELinux AVC denial lines leaked through the audit surface. This is audit-surface exposure, not direct proof of a root daemon." to R.string.detector_copy_card_selinux_avc_impact,
    "Readable auditpatch residue suggests audit denials could be relabeled or masked." to R.string.detector_copy_card_selinux_auditpatch_impact,
    "Policy drift may allow some restrictions to be bypassed." to R.string.detector_copy_card_selinux_policy_drift_impact,
    "Policy looks heavily weakened, so enforcement may be ineffective." to R.string.detector_copy_card_selinux_policy_weak_impact,
    "Violations are logged but not blocked." to R.string.detector_copy_card_selinux_violations_logged,
    "Security-sensitive apps and integrity checks may fail." to R.string.detector_copy_card_selinux_apps_impact,
    "Mandatory access control is completely disabled." to R.string.detector_copy_card_selinux_mac_disabled,
    "Android compatibility requires SELinux in global enforcing mode (CDD 9.7), so this build or boot configuration departs from a compatible one." to R.string.detector_copy_card_selinux_cdd,
    "Local probes were inconclusive." to R.string.detector_copy_card_selinux_inconclusive,
    "The app_zygote carrier validated both KSU-specific contexts in live policy." to R.string.detector_copy_card_selinux_context_validated,
    "The zygotePreload app_zygote carrier reported a coherent policyload/access seqno contract." to R.string.detector_copy_card_selinux_seqno_coherent,
    "The zygotePreload app_zygote seqno oracle stayed unavailable." to R.string.detector_copy_card_selinux_seqno_unavailable,
    "Repeatable attr/current timing asymmetry is strong device-side evidence of extra context processing before access denial. This device-dependent side channel alone does not identify a root tool." to R.string.detector_copy_card_selinux_timing_impact,
    "The App Zygote invalid-context A−B paired median was positive." to R.string.detector_copy_card_selinux_ab_median,
    "Stock kernels also take different paths for A and B, and CPU/load can change the sign." to R.string.detector_copy_card_selinux_stock_paths,
    "This is a strong timing anomaly, not proof of KernelSU or root." to R.string.detector_copy_card_selinux_timing_anomaly,
    "The AVC counts share the same measurement carrier." to R.string.detector_copy_card_selinux_avc_carrier,
    "The app_zygote SID-table experiment twice saw accepted context queries leave the live SID-table count unchanged and rejected attr/current writes increase it. This is supporting evidence, not tool identification or root proof." to R.string.detector_copy_card_selinux_sidtab_experiment,
    "Reduced coverage lowers confidence without implying a positive root detection." to R.string.detector_copy_card_nativeroot_reduced_confidence,
    "A determined root can still hide or remove residue, so absence of native hits is not proof of a stock device." to R.string.detector_copy_card_nativeroot_hide,
    "Native coverage was unavailable, so this card should not be treated as a strong clean verdict." to R.string.detector_copy_card_nativeroot_clean_unavailable,
    "PackageManager, createPackageContext + ZipFile, open APK descriptors, storage mirrors, loopback, IPC, accessibility, and native package-path probes are collecting local evidence." to R.string.detector_copy_detail_dangerousapps_collecting,
    "Dangerous app scan failed before inventory could be built." to R.string.detector_copy_detail_dangerousapps_failed,
    "Target callbacks repeatedly missed their deadlines while interleaved caller controls succeeded. This is lower-confidence timing evidence; scheduling and OEM behavior can also delay delivery." to R.string.detector_copy_detail_dangerousapps_timeout,
    "A returned Binder matched the Thanox runtime interface. This does not establish installation of the manager APK or package concealment." to R.string.detector_copy_detail_dangerousapps_thanox_matched,
    "Multiple fixed shared-storage baseline paths returned EACCES/EPERM under stat(). This suggests shared user gid or related zygote storage groups may have been restricted." to R.string.detector_copy_detail_dangerousapps_storage,
    "createPackageContext + ZipFile, open APK descriptor, and storage-side probes still ran, but a clean result may under-report installed tools when PackageManager visibility is scoped." to R.string.detector_copy_detail_dangerousapps_scoped,
    "PackageManager inventory was unavailable or anomalous, so package absence is inconclusive." to R.string.detector_copy_detail_dangerousapps_inventory_unknown,
    "Some UIDs held non-instant permissions while fresh package queries exposed no association. This experimental observation does not establish a hiding module." to R.string.detector_copy_detail_dangerousapps_uid,
    "No behavior mismatch was established, but some checks were partial, unavailable or inconclusive. Review each check's scope and controls." to R.string.detector_copy_detail_dangerousapps_behavior_incomplete,
    "The Thanox IPC check was unavailable or its reply could not be identified. No package presence or concealment is inferred from this response." to R.string.detector_copy_detail_dangerousapps_thanox_unavailable,
    "The package change history query did not complete successfully. Its missing evidence cannot establish that monitored packages have not appeared." to R.string.detector_copy_detail_dangerousapps_history_unavailable,
    "This boot's package change history includes monitored packages. Current installation and running state are unconfirmed; normal removal can leave the same evidence." to R.string.detector_copy_detail_dangerousapps_history_match,
    "PackageManager, createPackageContext + ZipFile, open APK descriptors, storage, loopback, IPC, accessibility, and native package-path probes did not surface known high-risk tools." to R.string.detector_copy_detail_dangerousapps_clean,
    "No compatible runtime service observed." to R.string.detector_copy_detail_thanox_not_observed,
    "Not collected." to R.string.detector_copy_detail_thanox_not_collected,
    "Compatible runtime interface observed; manager APK installation and concealment are unconfirmed." to R.string.detector_copy_detail_thanox_matched,
    "Probe unavailable; no package presence or concealment is inferred." to R.string.detector_copy_detail_thanox_unavailable,
    "Reply unrecognized; no package presence or concealment is inferred." to R.string.detector_copy_detail_thanox_inconclusive,
    "PAC configured; URL omitted; request-level proxy selection not evaluated." to R.string.detector_copy_detail_network_pac,
    "Access denied." to R.string.detector_copy_detail_network_access_denied,
    "Platform query or read failed." to R.string.detector_copy_detail_network_platform_failure,
    "Network disappeared or its properties became inaccessible." to R.string.detector_copy_detail_network_disappeared,
    "Collection budget exceeded." to R.string.detector_copy_detail_network_budget,
    "Metadata is malformed, ambiguous or not a regular file." to R.string.detector_copy_detail_network_invalid_metadata,
    "Not evaluated." to R.string.detector_copy_detail_network_not_evaluated,
    "Calling UID scope. A null result can mean disconnected or blocked." to R.string.detector_copy_detail_network_caller_scope,
    "Explicit process binding only; unbound does not mean offline." to R.string.detector_copy_detail_network_process_binding,
    "Framework-visible handles only; not every UID, profile, socket or kernel routing table." to R.string.detector_copy_detail_network_framework_visible,
    "Visible networks only; this does not establish this app's request path." to R.string.detector_copy_detail_network_visible_only,
    "Configuration only." to R.string.detector_copy_detail_network_configuration_only,
    "Exact package matches; installation does not establish service activity." to R.string.detector_copy_detail_network_exact_packages,
    "Disabled; zero requests and zero bytes sent." to R.string.detector_copy_detail_network_zero_requests,
    "Network-specific configuration only; no PAC fetch or request performed." to R.string.detector_copy_detail_network_no_pac_fetch,
    "Context only; not proxy evidence." to R.string.detector_copy_detail_network_dns_context,
    "Disabled. No endpoints, payloads, sockets or DNS requests; timeout not applicable; data budget 0 bytes, request budget 0." to R.string.detector_copy_detail_network_no_active_tests,
    "No privileged firewall rules, other-UID process state, module logs or per-request traffic observation. Enterprise VPNs, local filters, DNS64/NAT64 and captive portals are legitimate contexts." to R.string.detector_copy_detail_network_routing_limit,
    "No interface names or network handles in export; no addresses, PAC URLs, DNS hostnames, subscriptions, credentials or connection history retained." to R.string.detector_copy_detail_network_export_privacy,
    "ConnectivityManager and JVM static HTTP endpoint views; correlated sources, not independent evidence of traffic use. Process overrides and asynchronous updates can differ." to R.string.detector_copy_detail_network_proxy_sources,
    "Global proxy takes precedence, then the process-bound network, otherwise the calling UID's network. Configuration is not actual request use." to R.string.detector_copy_detail_network_proxy_precedence,
    "Process-local http.proxyHost/http.proxyPort only; host omitted. Partial or invalid pairs are inconclusive; exclusions, HTTPS/SOCKS and custom ProxySelectors are outside this check." to R.string.detector_copy_detail_network_jvm_proxy,
    "VPN transport does not establish proxying of this app's requests." to R.string.detector_copy_detail_network_vpn_proxy_boundary,
    "Warnings highlight observed VPN/proxy configuration, client packages or module deployment traces for review. Legitimate VPNs and tests can trigger them; service activity and request routing remain unevaluated." to R.string.detector_copy_detail_network_ready_summary,
    "LinkProperties routes only; addresses and gateways omitted." to R.string.detector_copy_detail_network_linkproperties,
    "Not probed. No ports scanned; changed ports and disabled control interfaces are outside coverage." to R.string.detector_copy_detail_network_module_not_probed,
    "Not evaluated. App exclusions and direct rules cannot be inferred from installation, TUN interfaces or service responses." to R.string.detector_copy_detail_network_module_not_evaluated,
    "Protected or renamed paths are outside coverage; metadata can be modified. Does not identify the running core or mechanism." to R.string.detector_copy_detail_network_module_metadata_limit,
    "Repeated reads are not atomic and cannot exclude intermediate changes." to R.string.detector_copy_detail_network_sample_non_atomic,
    "Boot consistency check unavailable because Attestation RootOfTrust was missing." to R.string.detector_copy_detail_tee_boot_consistency_missing_root,
    "The read-only ksu_driver probe was blocked by app seccomp on this device, so the verdict falls back to prctl, self-process IOC, path, cgroup, kernel-string, and property evidence." to R.string.detector_copy_detail_nativeroot_ksu_probe_blocked,
    "No comparable KeyMint VINTF declaration was found." to R.string.detector_copy_detail_tee_no_comparable_keymint_vintf,
    "Not enough paired samples were collected to judge certificate post-processing." to R.string.detector_copy_detail_tee_postprocessing_samples,
    "Skipped because the device did not expose a hardware-backed KeyMint tier." to R.string.detector_copy_detail_tee_postprocessing_skipped_hardware,
    "Skipped because the chain carried no RKP provisioning manufacturer to cross-check." to R.string.detector_copy_detail_tee_rkp_manufacturer_skipped,
    "Package matches, runtime interfaces and platform behavior checks have separate scopes. Behavior mismatches do not identify a hiding module; timing anomalies have lower confidence. Package history does not establish current installation, and none of these observations proves root access." to R.string.detector_copy_detail_dangerousapps_interpretation,
    "A listed probe ran in this scan. Zero hits do not establish full visibility; related package probes can share the same underlying mechanism." to R.string.detector_copy_detail_dangerousapps_probe_ran,
    "Fixed baseline paths returned EACCES/EPERM. This is a storage visibility indicator and does not identify an installed package or a hiding implementation." to R.string.detector_copy_detail_dangerousapps_storage_visibility,
    "Policy-backed Attestation anomalies were detected" to R.string.detector_copy_card_tee_tampered_headline,
    "Policy-backed Attestation evidence needs review" to R.string.detector_copy_card_tee_review_headline,
    "Hardware-backed local verification was not established" to R.string.detector_copy_card_tee_broken_headline,
    "Local verification stayed inconclusive" to R.string.detector_copy_card_tee_inconclusive_headline,
    "Local TEE verification failed" to R.string.detector_copy_card_tee_failed_headline,
    "Attestation aligned; local probes need review" to R.string.detector_copy_card_tee_consistent_review,
    "Attestation aligned; native probes did not run" to R.string.detector_copy_card_tee_consistent_native,
    "Local TEE Attestation checks aligned" to R.string.detector_copy_card_tee_consistent,
    "Attestation, trust path, and revocation checks line up." to R.string.detector_copy_card_tee_summary_consistent,
    "Attestation, trust path, and revocation checks line up, but the native process-side probes did not run." to R.string.detector_copy_card_tee_summary_native_unavailable,
    "Multiple hard anomaly indicators were raised." to R.string.detector_copy_card_tee_hard_anomalies,
    "Policy-backed review signals suggest further review." to R.string.detector_copy_card_tee_review_signals,
    "Local verification could not establish hardware-backed trust." to R.string.detector_copy_card_tee_local_untrusted,
    "Signals were mixed and did not converge on a stable local result." to R.string.detector_copy_card_tee_mixed_signals,
    "Collecting local Attestation and Keystore evidence." to R.string.detector_copy_card_tee_collecting,
    "Aligned • local review" to R.string.detector_copy_card_tee_aligned_local_review,
    "Aligned • native unavailable" to R.string.detector_copy_card_tee_aligned_native_unavailable,
    "Checks aligned" to R.string.detector_copy_card_tee_checks_aligned,
    "No hardware trust" to R.string.detector_copy_card_tee_no_hardware_trust,
    "Mixed signals" to R.string.detector_copy_card_tee_mixed,
    "Certificate signatures did not verify locally." to R.string.detector_copy_card_tee_certificate_failure,
    "Attestation challenge did not match the local request." to R.string.detector_copy_card_tee_challenge_failure,
    "Local trust path pending" to R.string.detector_copy_card_tee_trust_pending,
    "Local trust path unavailable" to R.string.detector_copy_card_tee_trust_unavailable,
    "RKP observed on an invalid local chain" to R.string.detector_copy_card_tee_trust_rkp_invalid,
    "RKP observed, local trust needs review" to R.string.detector_copy_card_tee_trust_rkp_review,
    "RKP observed" to R.string.detector_copy_card_tee_rkp_observed,
    "provisioning needs review" to R.string.detector_copy_card_tee_provisioning_review,
)

private val customRomSubtitleWithModification =
    Regex("""^(\d+) props · (\d+) mod props · (\d+) packages · (\d+) named services$""")
private val customRomSubtitleWithoutModification =
    Regex("""^(\d+) props · mod props unavailable · (\d+) packages · (\d+) named services$""")
private val listedServices = Regex("""^Listed (\d+) services\.$""")
private val signalCount = Regex("""^(\d+) (.+?) signal\(s\)( need review)?$""")
private val zygiskSubtitle = Regex("""^(\d+) strong · (\d+) heuristic · (\d+) signal\(s\)$""")
private const val packageHistoryScope =
    "History resets on reboot and may be filtered by package visibility or hiding modules. It cannot establish current installation, running state or concealment."
private val packageHistoryCount = Regex(
    """^(\d+) monitored package\(s\) appeared in visible changes since boot\. Additions, updates and removals share this list; event type and time are not provided\. (.+)$""",
)
private val packageHistorySequence = Regex("""^Returned sequence: (\d+)\.$""")
private val memoryNativeSubtitle = Regex("""^(\d+) native detector families · current-process memory only$""")
private val kernelCheckSubtitle = Regex("""^(\d+) keyword families · (\d+) cmdline rules · (native /proc|fallback file reads)$""")
private val mountSubtitle = Regex("""^(\d+) mounts · (\d+) mountinfo · (\d+) map lines$""")
private val kernelZwcBlocked = Regex("""^ZWC and (\d+) tested ignorable codepoints were blocked\.$""")
private val mountAccessibleChecks = Regex("""^Accessible checks: (\d+)/(\d+)\. Permission-denied checks: (\d+)\. Restricted visibility is not evidence of root\.$""")
private val suSubtitleNative = Regex("""^(\d+) su paths · (\d+) adb daemon paths · native /proc scan$""")
private val suSubtitleFallback = Regex("""^(\d+) su paths · (\d+) adb daemon paths · fallback self context$""")
private val virtualizationSubtitle = Regex("""^(\d+) env · (\d+) translation · (\d+) runtime(?: · (\d+) dex)?(?: · (\d+) uid)?(?: · (\d+) trap hit\(s\))?(?: · (\d+) host app\(s\))?$""")
private val selinuxSubtitle = Regex("""^(\d+) local checks( \+ attr/current timing)?( \+ app_zygote AVC counters)?( \+ policy)?( \+ audit integrity \+ side-channel)?$""")
private val rootManagerConcealedSummary = Regex(
    """^Identified (\d+) root manager app\(s\); at least one disabled its launcher icon and is reachable only through app details\. (.+)$""",
)
private val locationRiskSyntheticDetail = Regex(
    """^Up to two synthetic objects; no real fix\. Fields: (.+?)\.(.*)$""",
)
private val teeTrustSummary = Regex(
    """^Local trust path: (.+?), chain (verified|failed)(?:, (.+))?$""",
)
private val dangerousAppsSubtitle = Regex(
    """^(\d+) legacy targets(?: · (full|scoped) PM inventory)?(?: · (\d+) visible)?$""",
)
private val dangerousAppsVisibilityCount = Regex("""^(Full|Scoped) · (\d+)$""")
private val networkIndexedRowLabel = Regex("""^Network (\d+) (transports|interface / routes|link proxy / PAC|Private DNS)$""")
private val networkModuleRowLabel = Regex("""^(Box4Magisk|Box for Root) (deployment trace|service response|traffic effect)$""")
private val networkStateLocalHandle = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive) \(local handle (\d+)\)$""")
private val networkStateReturnedCount = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive); (\d+) returned$""")
private val networkStatePort = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive); port (\d+)$""")
private val networkStateSuffix = Regex("""^(Observed|Not observed|Unavailable|Permission limited|Unsupported|Inconclusive); (.+)$""")
private val networkRouteSummary = Regex("""^(\d+) routes \(IPv4 (\d+), IPv6 (\d+), default (\d+)\)$""")
private val dangerousAppsRiskyPackageCount = Regex("""^(\d+) risky package\(s\) surfaced$""")
private val dangerousAppsSignalCount = Regex("""^(\d+) signal\(s\)$""")
private val dangerousAppsPackageHitCount = Regex("""^(\d+) package hit\(s\)$""")
private val dangerousAppsLegacyPackages = Regex("""^(\d+) legacy packages$""")
private val dangerousAppsMatchedSummary = Regex(
    """^Matched (\d+) package\(s\) across (\d+) category\(ies\)\. All package hits stay warning-level unless HMA concealment is present\.(?: PackageManager still exposed only (\d+) visible packages, which is unusually low and can happen under HMA-style whitelist filtering\.)?$""",
)
private val teePolicySignalCounts = Regex("""^(\d+) policy hard • (\d+) policy review • (\d+) local$""")
private val teeChainLayout = Regex("""^len (\d+) • ext (\d+) • trusted (#[1-9]\d*|n/a)$""")
private val teeVersions = Regex("""^attest (.+?) • keymaster (.+?) • Android (.+)$""")
private val lsposedSubtitle = Regex("""^(\d+) manager · (\d+) module · (\d+) native(?: · (\d+) policy)?$""")
private val nativeRootSubtitle = Regex("""^(\d+) paths · (\d+) proc entries · (\d+) cgroup dirs · (\d+) kernel sources · (\d+) props$""")
private val playIntegritySubtitle = Regex("""^(\d+) props · (\d+) hits · (\d+) mismatch · (\d+) traces$""")
private val heapBytes = Regex("""^(\d+) bytes$""")
private val rootManagersSubtitle = Regex("""^(\d+) matched · (\d+) apps checked · (\d+) profile\(s\) searched$""")
private val rootManagersAppsChecked = Regex("""^(\d+) apps checked$""")
private val rootManagersMatches = Regex("""^(\d+) match\(es\)$""")
private val rootManagersProfileStats = Regex("""^(\d+) apps checked · (\d+) match\(es\)$""")
private val countOfCount = Regex("""^(\d+) of (\d+)$""")
private val countReadFailed = Regex("""^(\d+) read · (\d+) failed$""")
private val profileUserLabel = Regex("""^user (\d+)$""")
private val rootManagersFoundSummary = Regex("""^Identified (\d+) root manager app\(s\) across (\d+) profile\(s\), (\d+) by a family kernel's manager key\. (.+)$""")
private val rootManagersCleanSummary = Regex("""^Checked (\d+) app\(s\) across (\d+) profile\(s\), including (\d+) signing certificates, and matched no root manager app\.$""")
private val rootManagersPartialSummary = Regex("""^No root manager matched, but (.+), so the absence of matches is not proof\.$""")
private val rootManagersPermissionOwnerSummary = Regex("""^(.+) declares the candidate KernelSU permission\. (.+)$""")
private val rootManagersEntryDetail = Regex("""^@user (\d+) · anchors: (.+?)(?: · signed with the (.+?) manager key)?(?: · payload: (.+?))?( · launcher icon hidden)?$""")
/**
 * Resolves known detector copy at the Android UI boundary.
 *
 * Detector presentation modules intentionally remain plain Kotlin/JVM and therefore cannot read
 * Android resources. Their stable English copy is used as a lookup key here; raw evidence,
 * package names, property values, paths, and unknown diagnostic text pass through unchanged.
 */
@Composable
public fun localizeDetectorCopy(text: String): String {
    // Preserve machine-facing evidence and diagnostic records verbatim. These strings are often
    // compared with kernel logs, policy rules, probe output, or upstream protocol documentation.
    if (text.contains("Evidence source=") ||
        text.contains("Observed edge:") ||
        text.contains("Controlled app_zygote writes repeatedly recognized privileged contexts:") ||
        text.contains("DirtySepolicy 2.2 compatibility:")
    ) return text

    playIntegritySubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_playintegrityfix_counts,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
            match.groupValues[4].toInt(),
        )
    }
    heapBytes.matchEntire(text)?.let { match ->
        val bytes = match.groupValues[1].toLongOrNull() ?: return text
        return stringResource(R.string.detector_copy_value_bytes, bytes)
    }
    rootManagersPartialSummary.matchEntire(text)?.let { match ->
        val localizedGaps = mutableListOf<String>()
        for (gap in match.groupValues[1].split(", ")) {
            localizedGaps += localizeDetectorCopy(gap)
        }
        return stringResource(R.string.detector_copy_card_rootmanagers_partial, localizedGaps.joinToString("、"))
    }
    rootManagersSubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_rootmanagers,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    rootManagersAppsChecked.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_rootmanagers_apps_checked, match.groupValues[1].toInt())
    }
    rootManagersMatches.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_rootmanagers_matches, match.groupValues[1].toInt())
    }
    rootManagersProfileStats.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_rootmanagers_profile_stats,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
    }
    countOfCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_count_of_count, match.groupValues[1].toInt(), match.groupValues[2].toInt())
    }
    countReadFailed.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_count_read_failed, match.groupValues[1].toInt(), match.groupValues[2].toInt())
    }
    profileUserLabel.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_label_profile_user, match.groupValues[1].toInt())
    }
    rootManagersFoundSummary.matchEntire(text)?.let { match ->
        val summary = stringResource(
            R.string.detector_copy_card_rootmanagers_found,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
        return "$summary ${localizeDetectorCopy(match.groupValues[4])}"
    }
    rootManagersCleanSummary.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_card_rootmanagers_clean,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    rootManagersPermissionOwnerSummary.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_card_rootmanagers_permission_owner,
            match.groupValues[1],
            localizeDetectorCopy(match.groupValues[2]),
        )
    }
    rootManagersEntryDetail.matchEntire(text)?.let { match ->
        val localizedAnchors = StringBuilder()
        val anchorParts = match.groupValues[2].split(", ")
        for (index in anchorParts.indices) {
            if (index > 0) localizedAnchors.append(", ")
            localizedAnchors.append(localizeDetectorCopy(anchorParts[index]))
        }
        val anchors = localizedAnchors.toString()
        val signedWith = match.groupValues[3].takeIf(String::isNotEmpty)?.let {
            stringResource(R.string.detector_copy_value_rootmanagers_signed_with_key, it)
        }.orEmpty()
        val payload = match.groupValues[4].takeIf(String::isNotEmpty)?.let {
            stringResource(R.string.detector_copy_value_rootmanagers_payload, it)
        }.orEmpty()
        val iconHidden = if (match.groupValues[5].isNotEmpty()) {
            stringResource(R.string.detector_copy_value_rootmanagers_icon_hidden)
        } else {
            ""
        }
        return stringResource(
            R.string.detector_copy_value_rootmanagers_entry_detail,
            match.groupValues[1].toInt(),
            anchors,
            signedWith,
            payload,
            iconHidden,
        )
    }
    nativeRootSubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_nativeroot_counts,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
            match.groupValues[4].toInt(),
            match.groupValues[5].toInt(),
        )
    }
    lsposedSubtitle.matchEntire(text)?.let { match ->
        val managers = match.groupValues[1].toInt()
        val modules = match.groupValues[2].toInt()
        val native = match.groupValues[3].toInt()
        val policy = match.groupValues[4]
        return if (policy.isEmpty()) {
            stringResource(R.string.detector_copy_subtitle_lsposed_counts, managers, modules, native)
        } else {
            stringResource(
                R.string.detector_copy_subtitle_lsposed_counts_with_policy,
                managers,
                modules,
                native,
                policy.toInt(),
            )
        }
    }
    teeVersions.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_tee_versions,
            match.groupValues[1],
            match.groupValues[2],
            match.groupValues[3],
        )
    }
    teeChainLayout.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_tee_chain_layout,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3],
        )
    }
    teePolicySignalCounts.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_tee_policy_signal_counts,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    dangerousAppsRiskyPackageCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_dangerousapps_verdict_risky_packages, match.groupValues[1].toInt())
    }
    dangerousAppsMatchedSummary.matchEntire(text)?.let { match ->
        val base = stringResource(
            R.string.detector_copy_dangerousapps_summary_matched_packages,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
        val lowInventoryCount = match.groupValues[3]
        return if (lowInventoryCount.isEmpty()) base else {
            "$base ${stringResource(R.string.detector_copy_dangerousapps_summary_low_inventory, lowInventoryCount.toInt())}"
        }
    }
    dangerousAppsSignalCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_signal_count, match.groupValues[1].toInt())
    }
    dangerousAppsPackageHitCount.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_package_hit_count, match.groupValues[1].toInt())
    }
    dangerousAppsLegacyPackages.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_value_legacy_packages, match.groupValues[1].toInt())
    }
    networkStateLocalHandle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_network_local_handle,
            localizeDetectorCopy(match.groupValues[1]),
            match.groupValues[2],
        )
    }
    networkStateReturnedCount.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_network_returned_count,
            localizeDetectorCopy(match.groupValues[1]),
            match.groupValues[2].toInt(),
        )
    }
    networkStatePort.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_value_network_port,
            localizeDetectorCopy(match.groupValues[1]),
            match.groupValues[2].toInt(),
        )
    }
    networkStateSuffix.matchEntire(text)?.let { match ->
        val localizedParts = mutableListOf<String>()
        for (part in match.groupValues[2].split("; ")) {
            val route = networkRouteSummary.matchEntire(part)
            localizedParts += if (route == null) {
                part
            } else {
                stringResource(
                    R.string.detector_copy_value_network_routes,
                    route.groupValues[1].toInt(),
                    route.groupValues[2].toInt(),
                    route.groupValues[3].toInt(),
                    route.groupValues[4].toInt(),
                )
            }
        }
        val localizedSuffix = localizedParts.joinToString("; ")
        return "${localizeDetectorCopy(match.groupValues[1])}; $localizedSuffix"
    }
    networkIndexedRowLabel.matchEntire(text)?.let { match ->
        val resource = when (match.groupValues[2]) {
            "transports" -> R.string.detector_copy_label_network_transports
            "interface / routes" -> R.string.detector_copy_label_network_interface_routes
            "link proxy / PAC" -> R.string.detector_copy_label_network_link_proxy
            "Private DNS" -> R.string.detector_copy_label_network_private_dns
            else -> return text
        }
        return stringResource(resource, match.groupValues[1].toInt())
    }
    networkModuleRowLabel.matchEntire(text)?.let { match ->
        val resource = when (match.groupValues[2]) {
            "deployment trace" -> R.string.detector_copy_label_network_module_deployment
            "service response" -> R.string.detector_copy_label_network_module_service
            "traffic effect" -> R.string.detector_copy_label_network_module_traffic
            else -> return text
        }
        return stringResource(resource, match.groupValues[1])
    }
    dangerousAppsSubtitle.matchEntire(text)?.let { match ->
        val parts = mutableListOf(
            stringResource(R.string.detector_copy_subtitle_dangerousapps_targets, match.groupValues[1].toInt()),
        )
        when (match.groupValues[2]) {
            "full" -> parts += stringResource(R.string.detector_copy_subtitle_dangerousapps_full_pm)
            "scoped" -> parts += stringResource(R.string.detector_copy_subtitle_dangerousapps_scoped_pm)
        }
        match.groupValues[3].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_dangerousapps_visible, it.toInt())
        }
        return parts.joinToString(" · ")
    }
    dangerousAppsVisibilityCount.matchEntire(text)?.let { match ->
        return "${localizeDetectorCopy(match.groupValues[1])} · ${match.groupValues[2]}"
    }
    teeTrustSummary.matchEntire(text)?.let { match ->
        val trustRoot = localizeDetectorCopy(match.groupValues[1])
        val chainState = localizeDetectorCopy(match.groupValues[2])
        val suffix = match.groupValues[3].takeIf(String::isNotBlank)
            ?.let { ", ${localizeDetectorCopy(it)}" }
            .orEmpty()
        return stringResource(
            R.string.detector_copy_card_tee_trust_path_template,
            trustRoot,
            chainState,
            suffix,
        )
    }
    rootManagerConcealedSummary.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return text
        return stringResource(
            R.string.detector_copy_card_rootmanagers_hidden_icon,
            count,
            localizeDetectorCopy(match.groupValues[2]),
        )
    }
    locationRiskSyntheticDetail.matchEntire(text)?.let { match ->
        val fields = match.groupValues[1]
        val tail = match.groupValues[2].replace(
            "Public setMock requires API 31; older releases are unsupported.",
            stringResource(R.string.detector_copy_card_locationrisk_setmock),
        )
        return stringResource(R.string.detector_copy_card_locationrisk_synthetic, fields) + tail
    }
    suSubtitleNative.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_su_native,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
    }
    suSubtitleFallback.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_subtitle_su_fallback,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
        )
    }
    virtualizationSubtitle.matchEntire(text)?.let { match ->
        val parts = mutableListOf(
            stringResource(
                R.string.detector_copy_subtitle_virtualization,
                match.groupValues[1].toInt(),
                match.groupValues[2].toInt(),
                match.groupValues[3].toInt(),
            ),
        )
        match.groupValues[4].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_dex, it.toInt())
        }
        match.groupValues[5].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_uid, it.toInt())
        }
        match.groupValues[6].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_traps, it.toInt())
        }
        match.groupValues[7].takeIf(String::isNotEmpty)?.let {
            parts += stringResource(R.string.detector_copy_subtitle_virtualization_host_apps, it.toInt())
        }
        return parts.joinToString(" · ")
    }
    selinuxSubtitle.matchEntire(text)?.let { match ->
        val parts = mutableListOf(
            stringResource(R.string.detector_copy_subtitle_selinux_base, match.groupValues[1].toInt()),
        )
        if (match.groupValues[2].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_attr_timing)
        }
        if (match.groupValues[3].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_avc_counters)
        }
        if (match.groupValues[4].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_policy)
        }
        if (match.groupValues[5].isNotEmpty()) {
            parts += stringResource(R.string.detector_copy_subtitle_selinux_audit)
        }
        return parts.joinToString(" + ")
    }
    memoryNativeSubtitle.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_subtitle_memory_native, count)
    }
    kernelCheckSubtitle.matchEntire(text)?.let { match ->
        val keywordCount = match.groupValues[1].toIntOrNull() ?: return text
        val ruleCount = match.groupValues[2].toIntOrNull() ?: return text
        val source = stringResource(
            if (match.groupValues[3] == "native /proc") {
                R.string.detector_copy_value_native_proc
            } else {
                R.string.detector_copy_value_fallback_file_reads
            },
        )
        return stringResource(R.string.detector_copy_subtitle_kernel_check, keywordCount, ruleCount, source)
    }
    mountSubtitle.matchEntire(text)?.let { match ->
        val mounts = match.groupValues[1].toIntOrNull() ?: return text
        val mountInfo = match.groupValues[2].toIntOrNull() ?: return text
        val mapLines = match.groupValues[3].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_subtitle_mount, mounts, mountInfo, mapLines)
    }
    kernelZwcBlocked.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_detail_kernel_zwc_blocked, count)
    }
    mountAccessibleChecks.matchEntire(text)?.let { match ->
        val accessible = match.groupValues[1].toIntOrNull() ?: return text
        val total = match.groupValues[2].toIntOrNull() ?: return text
        val denied = match.groupValues[3].toIntOrNull() ?: return text
        return stringResource(R.string.detector_copy_detail_mount_accessible_checks, accessible, total, denied)
    }

    if (text.endsWith(packageHistoryScope)) {
        val observation = text.removeSuffix(packageHistoryScope).trimEnd()
        val localizedObservation = when (observation) {
            "Not collected." -> stringResource(R.string.detector_copy_package_history_not_collected)
            "Permission denied; change history is unavailable." ->
                stringResource(R.string.detector_copy_package_history_permission_denied)
            "Query failed; change history is unavailable." ->
                stringResource(R.string.detector_copy_package_history_query_failed)
            "Invalid response; change history could not be evaluated." ->
                stringResource(R.string.detector_copy_package_history_invalid_response)
            else -> {
                val match = packageHistoryCount.matchEntire(observation) ?: return text
                val count = match.groupValues[1].toIntOrNull() ?: return text
                val tail = match.groupValues[2]
                val suffix = packageHistorySequence.matchEntire(tail)?.let {
                    stringResource(R.string.detector_copy_package_history_sequence, it.groupValues[1])
                } ?: if (tail == "No visible changes or sequence number were returned.") {
                    stringResource(R.string.detector_copy_package_history_no_visible_changes)
                } else {
                    return text
                }
                pluralStringResource(R.plurals.detector_copy_package_history_count, count, count) + " " + suffix
            }
        }
        return localizedObservation + " " + stringResource(R.string.detector_copy_package_history_scope)
    }
    val unattributedDirectoryActivityPrefix = "Unattributed directory activity; diagnostic only."
    if (text.startsWith(unattributedDirectoryActivityPrefix)) {
        return stringResource(R.string.detector_copy_detail_diagnostic_nativeroot_unattributed_directory_activity) +
            text.removePrefix(unattributedDirectoryActivityPrefix)
    }
    customRomSubtitleWithModification.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_customrom_subtitle_full,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
            match.groupValues[4].toInt(),
        )
    }
    customRomSubtitleWithoutModification.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_customrom_subtitle_no_mod,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }
    listedServices.matchEntire(text)?.let { match ->
        return stringResource(R.string.detector_copy_detail_listed_services, match.groupValues[1].toInt())
    }
    signalCount.matchEntire(text)?.let { match ->
        val count = match.groupValues[1].toIntOrNull() ?: return@let
        val noun = localizeSignalNoun(match.groupValues[2]) ?: return@let
        return if (match.groupValues[3].isNotEmpty()) {
            pluralStringResource(R.plurals.detector_copy_signal_review, count, count, noun)
        } else {
            pluralStringResource(R.plurals.detector_copy_signal_count, count, count, noun)
        }
    }
    zygiskSubtitle.matchEntire(text)?.let { match ->
        return stringResource(
            R.string.detector_copy_zygisk_subtitle,
            match.groupValues[1].toInt(),
            match.groupValues[2].toInt(),
            match.groupValues[3].toInt(),
        )
    }

    detectorCopyLabelResources[text]?.let { return stringResource(it) }
    detectorCopyValueResources[text]?.let { return stringResource(it) }
    detectorCopyDetailResources[text]?.let { return stringResource(it) }

    // Some card summaries concatenate several independently-authored sentences. Translate the
    // known sentences in place while preserving dynamic values and raw diagnostic evidence.
    var localizedComposite = text
    mapOf(
        "caller default" to R.string.detector_copy_value_network_caller_default,
        "process bound" to R.string.detector_copy_value_network_process_bound,
        "other visible" to R.string.detector_copy_value_network_other_visible,
    ).forEach { (source, resource) ->
        localizedComposite = localizedComposite.replace(source, stringResource(resource))
    }
    detectorCopyDetailResources.entries
        .asSequence()
        .filter { (source, _) -> source.length >= 36 && localizedComposite.contains(source) }
        .sortedByDescending { it.key.length }
        .forEach { (source, resource) ->
            localizedComposite = localizedComposite.replace(source, stringResource(resource))
        }
    if (localizedComposite != text) return localizedComposite

    return when (text) {
        "Custom ROM" -> stringResource(R.string.detector_copy_title_custom_rom)
        "System Properties" -> stringResource(R.string.detector_copy_title_system_properties)
        "ADB Runtime" -> stringResource(R.string.detector_copy_title_adb_runtime)
        "Dangerous Apps" -> stringResource(R.string.detector_copy_title_dangerous_apps)
        "Mount" -> stringResource(R.string.detector_copy_title_mount)
        "Native Root" -> stringResource(R.string.detector_copy_title_native_root)
        "Network Risk" -> stringResource(R.string.detector_copy_title_network_risk)
        "Memory" -> stringResource(R.string.detector_copy_title_memory)
        "SELinux" -> stringResource(R.string.detector_copy_title_selinux)
        "Bootloader" -> stringResource(R.string.detector_copy_title_bootloader)
        "Zygisk" -> stringResource(R.string.detector_copy_title_zygisk)
        "Virtualization" -> stringResource(R.string.detector_copy_title_virtualization)
        "Device Info" -> stringResource(R.string.detector_copy_title_device_info)
        "Location Risk" -> stringResource(R.string.detector_copy_title_location_risk)
        "Kernel Check" -> stringResource(R.string.detector_copy_title_kernel_check)
        "Play Integrity Fix" -> stringResource(R.string.detector_copy_title_play_integrity_fix)
        "Root Managers" -> stringResource(R.string.detector_copy_title_root_managers)
        "Zygote heap residue" -> stringResource(R.string.detector_copy_title_heap_residue)
        "Clean" -> stringResource(R.string.detector_copy_state_clean)
        "Readable" -> stringResource(R.string.detector_copy_readable)
        "Loading" -> stringResource(R.string.detector_copy_loading)
        "Exposed" -> stringResource(R.string.detector_copy_exposed)
        "Protected" -> stringResource(R.string.detector_copy_protected)
        "Blocked by seccomp" -> stringResource(R.string.detector_copy_blocked_by_seccomp)
        "Danger" -> stringResource(R.string.status_danger)
        "Review" -> stringResource(R.string.detector_copy_review)
        "Host" -> stringResource(R.string.detector_copy_host)
        "HMA mismatch" -> stringResource(R.string.detector_copy_hma_mismatch)
        "Detected Packages" -> stringResource(R.string.detector_copy_detected_packages)
        "Package Changes Since Boot" -> stringResource(R.string.detector_copy_package_changes_since_boot)
        "Environment & Network" -> stringResource(R.string.detector_copy_environment_network)
        "Anomalies" -> stringResource(R.string.detector_copy_anomalies)
        "None" -> stringResource(R.string.detector_copy_state_none)
        "Unavailable" -> stringResource(R.string.detector_copy_state_unavailable)
        "Pending" -> stringResource(R.string.detector_copy_state_pending)
        "Error" -> stringResource(R.string.status_info_error)
        "Failed" -> stringResource(R.string.detector_copy_state_failed)
        "Scoped" -> stringResource(R.string.detector_copy_state_scoped)
        "Full" -> stringResource(R.string.detector_copy_state_full)
        "Active" -> stringResource(R.string.detector_copy_state_active)
        "Not observed" -> stringResource(R.string.detector_copy_state_not_observed)
        "Scanning" -> stringResource(R.string.detector_copy_state_scanning)
        "Scan failed" -> stringResource(R.string.detector_copy_state_scan_failed)
        "Not evaluated" -> stringResource(R.string.detector_copy_state_not_evaluated)
        "Contradiction" -> stringResource(R.string.detector_copy_state_contradiction)
        "Present" -> stringResource(R.string.detector_copy_state_present)
        "Absent" -> stringResource(R.string.detector_copy_state_absent)
        "Permission required", "permission required" ->
            stringResource(R.string.detector_copy_state_permission_required)
        "Not probed", "not probed" -> stringResource(R.string.detector_copy_state_not_probed)
        "Not observable", "not observable" ->
            stringResource(R.string.detector_copy_state_not_observable)
        "Confirmed", "confirmed" -> stringResource(R.string.detector_copy_state_confirmed)
        "Not confirmed", "not confirmed" ->
            stringResource(R.string.detector_copy_state_not_confirmed)
        "Restricted" -> stringResource(R.string.detector_copy_state_restricted)
        "Limited" -> stringResource(R.string.detector_copy_state_limited)
        "Saved locally" -> stringResource(R.string.detector_copy_state_saved_locally)
        "Size limit exceeded" -> stringResource(R.string.detector_copy_state_size_limit_exceeded)
        "Retention failed" -> stringResource(R.string.detector_copy_state_retention_failed)
        "Full inventory access" -> stringResource(R.string.detector_copy_state_full_inventory_access)
        "Scoped inventory access" -> stringResource(R.string.detector_copy_state_scoped_inventory_access)
        "No target trace observed" -> stringResource(R.string.detector_copy_state_no_target_trace)
        "Target argument traces observed" ->
            stringResource(R.string.detector_copy_state_target_argument_traces)
        "Present (label denied)" -> stringResource(R.string.detector_copy_state_present_label_denied)
        "Present, init reports stopped" ->
            stringResource(R.string.detector_copy_state_present_init_stopped)
        "unavailable" -> stringResource(R.string.detector_copy_state_unavailable)
        "N/A" -> stringResource(R.string.detector_copy_state_na)
        "Unknown" -> stringResource(R.string.detector_copy_state_unknown)
        "Normal" -> stringResource(R.string.detector_copy_state_normal)
        "Abnormal" -> stringResource(R.string.detector_copy_state_abnormal)
        "Disabled" -> stringResource(R.string.detector_copy_state_disabled)
        "Enabled" -> stringResource(R.string.detector_copy_state_enabled)
        "Not reported" -> stringResource(R.string.detector_copy_state_not_reported)
        "Not resolved yet" -> stringResource(R.string.detector_copy_state_not_resolved)
        "Unsupported" -> stringResource(R.string.detector_copy_state_unsupported)
        "Inconclusive" -> stringResource(R.string.detector_copy_state_inconclusive)
        "Ready" -> stringResource(R.string.detector_copy_state_ready)
        "Probe unavailable" -> stringResource(R.string.detector_copy_state_probe_unavailable)
        "Detected" -> stringResource(R.string.detector_copy_state_detected)
        "Partial" -> stringResource(R.string.detector_copy_state_partial)
        "Support" -> stringResource(R.string.detector_copy_state_support)
        "OK" -> stringResource(R.string.detector_copy_state_clean)
        "Clear" -> stringResource(R.string.status_all_clear)
        "Warning" -> stringResource(R.string.status_warning)
        "Experimental ART snapshot · low confidence" ->
            stringResource(R.string.detector_copy_subtitle_heap_residue)
        "Location API contracts and optional cached mock metadata" ->
            stringResource(R.string.detector_copy_subtitle_location_risk)
        "Network context, proxy configuration and client evidence" ->
            stringResource(R.string.detector_copy_subtitle_network_risk)
        "ROMs" -> stringResource(R.string.detector_copy_label_roms)
        "Runtime" -> stringResource(R.string.detector_copy_label_runtime)
        "Build" -> stringResource(R.string.detector_copy_label_build)
        "Native" -> stringResource(R.string.detector_copy_label_native)
        "System properties" -> stringResource(R.string.detector_copy_label_system_properties)
        "Build fields" -> stringResource(R.string.detector_copy_label_build_fields)
        "Modification" -> stringResource(R.string.detector_copy_label_modification)
        "Packages" -> stringResource(R.string.detector_copy_label_packages)
        "Services" -> stringResource(R.string.detector_copy_label_services)
        "Reflection" -> stringResource(R.string.detector_copy_label_reflection)
        "Properties checked" -> stringResource(R.string.detector_copy_label_properties_checked)
        "Build fields checked" -> stringResource(R.string.detector_copy_label_build_fields_checked)
        "Modification props checked" -> stringResource(R.string.detector_copy_label_modification_props_checked)
        "Prop area contexts" -> stringResource(R.string.detector_copy_label_prop_area_contexts)
        "Prop area anomalies" -> stringResource(R.string.detector_copy_label_prop_area_anomalies)
        "Prop item anomalies" -> stringResource(R.string.detector_copy_label_prop_item_anomalies)
        "Packages checked" -> stringResource(R.string.detector_copy_label_packages_checked)
        "Package visibility" -> stringResource(R.string.detector_copy_label_package_visibility)
        "Named services checked" -> stringResource(R.string.detector_copy_label_named_services_checked)
        "Services listed" -> stringResource(R.string.detector_copy_label_services_listed)
        "Native library" -> stringResource(R.string.detector_copy_label_native_library)
        "Inconsistencies" -> stringResource(R.string.ui_section_inconsistencies)
        "Signals" -> stringResource(R.string.ui_section_signals)
        "Impact" -> stringResource(R.string.ui_section_impact)
        "Detection methods" -> stringResource(R.string.ui_section_detection_methods)
        "Scan summary" -> stringResource(R.string.ui_section_scan_summary)
        "No findings were produced for this section on this device." ->
            stringResource(R.string.detector_copy_detail_no_findings)
        "Native property-area coverage was unavailable on this build." ->
            stringResource(R.string.detector_copy_detail_native_property_area_unavailable)
        "Native symbol trace detection only runs on Android 10+." ->
            stringResource(R.string.detector_copy_detail_native_symbol_android_min)
        "Custom ROM scan has reduced coverage" ->
            stringResource(R.string.detector_copy_customrom_verdict_reduced_coverage)
        "Available probes were clean, but package visibility, property-area, or native symbol coverage was incomplete on this build." ->
            stringResource(R.string.detector_copy_customrom_summary_reduced_coverage)
        "Attestation aligned; local probes need review" ->
            stringResource(R.string.detector_copy_tee_verdict_local_review)
        "Keystore errors during timing skip matched a known keystore-interception module. Attestation and trust-path checks still aligned." ->
            stringResource(R.string.detector_copy_tee_summary_keystore_intercept)
        "ADB enabled" -> stringResource(R.string.detector_copy_adb_verdict_enabled)
        "ADB is enabled or runtime activity was observed; no persistent hard runtime contradiction was confirmed." ->
            stringResource(R.string.detector_copy_adb_summary_enabled)
        "Platform behavior mismatch observed" ->
            stringResource(R.string.detector_copy_dangerousapps_verdict_behavior_mismatch)
        "HMA-style concealment detected" ->
            stringResource(R.string.detector_copy_dangerousapps_verdict_hma)
        "Repeated callback timeout asymmetry" ->
            stringResource(R.string.detector_copy_dangerousapps_verdict_timeout)
        "No known risky packages" ->
            stringResource(R.string.detector_copy_dangerousapps_verdict_no_known_risky_packages)
        "Controlled interface checks observed inconsistent exception, broadcast callback, UID visibility or seccomp getpriority behavior. These signals do not identify a specific hiding module." ->
            stringResource(R.string.detector_copy_dangerousapps_summary_behavior_mismatch)
        "Network risk indicators observed" ->
            stringResource(R.string.detector_copy_network_verdict_observed)
        "Network risk indicators observed; context incomplete" ->
            stringResource(R.string.detector_copy_network_verdict_observed_incomplete)
        "Network risk indicators observed; network changed during scan" ->
            stringResource(R.string.detector_copy_network_verdict_observed_changed)
        "Network context incomplete" ->
            stringResource(R.string.detector_copy_network_verdict_context_incomplete)
        "Network changed during scan" ->
            stringResource(R.string.detector_copy_network_verdict_changed)
        "Network context collected" ->
            stringResource(R.string.detector_copy_network_verdict_collected)
        "Collecting caller-visible evidence." ->
            stringResource(R.string.detector_copy_network_summary_collecting)
        "ADB state consistent" -> stringResource(R.string.detector_copy_adb_verdict_consistent)
        "Independent ADB state sources disagree. The rows below show the persistent contradictions." ->
            stringResource(R.string.detector_copy_adb_summary_sources_disagree)
        "No persistent contradiction was observed across the ADB state sources that were available." ->
            stringResource(R.string.detector_copy_adb_summary_no_contradiction)
        else -> text
    }
}

@Composable
private fun localizeSignalNoun(noun: String): String? = when (noun) {
    "property" -> stringResource(R.string.detector_copy_signal_noun_property)
    "native" -> stringResource(R.string.detector_copy_signal_noun_native)
    "mount" -> stringResource(R.string.detector_copy_signal_noun_mount)
    "critical mount" -> stringResource(R.string.detector_copy_signal_noun_critical_mount)
    "startup" -> stringResource(R.string.detector_copy_signal_noun_startup)
    "critical startup" -> stringResource(R.string.detector_copy_signal_noun_critical_startup)
    "DRM consistency" -> stringResource(R.string.detector_copy_signal_noun_drm_consistency)
    "boot state" -> stringResource(R.string.detector_copy_signal_noun_boot_state)
    "critical boot integrity" -> stringResource(R.string.detector_copy_signal_noun_critical_boot_integrity)
    "high-risk property or coherence" -> stringResource(R.string.detector_copy_signal_noun_high_risk_property_coherence)
    "suspicious kernel" -> stringResource(R.string.detector_copy_signal_noun_suspicious_kernel)
    "high-risk LSPosed" -> stringResource(R.string.detector_copy_signal_noun_high_risk_lsposed)
    "LSPosed residue" -> stringResource(R.string.detector_copy_signal_noun_lsposed_residue)
    "direct virtualization" -> stringResource(R.string.detector_copy_signal_noun_direct_virtualization)
    "virtualization" -> stringResource(R.string.detector_copy_signal_noun_virtualization)
    "runtime root" -> stringResource(R.string.detector_copy_signal_noun_runtime_root)
    "high-risk memory" -> stringResource(R.string.detector_copy_signal_noun_high_risk_memory)
    "high-confidence residue" -> stringResource(R.string.detector_copy_signal_noun_high_confidence_residue)
    "strong" -> stringResource(R.string.detector_copy_signal_noun_strong)
    "direct runtime" -> stringResource(R.string.detector_copy_signal_noun_direct_runtime)
    "modification" -> stringResource(R.string.detector_copy_signal_noun_modification)
    "signal" -> stringResource(R.string.detector_copy_signal_noun_generic)
    else -> null
}
