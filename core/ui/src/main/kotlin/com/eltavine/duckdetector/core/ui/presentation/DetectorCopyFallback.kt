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
import androidx.compose.ui.res.stringResource
import com.eltavine.duckdetector.core.ui.R

@Composable
internal fun localizeDetectorCopyFallback(text: String): String = when (text) {
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
