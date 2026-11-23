# Copyright 2026 Duck Apps Contributor
# If you have any questions, suggestions, or other inquiries, please email Eltavine <me@eltavine.com>.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

duckdetector_native_unit(duckdetector_selinuxpolicy
    context_validity_checks.cpp
    context_validity_probe.cpp
    context_validity_symbols.cpp
    context_validity_native_bridge.cpp
    ksu_types_timing.cpp
    xxksu_fd_reuse.cpp
    raw_context_node.cpp
    dirty_policy_probe.cpp
    selinux_status_page_native_bridge.cpp
    sidtab_probe.cpp
    sidtab_probe_io.cpp
    sidtab_native_bridge.cpp
    proc_attr_probe.cpp
    proc_attr_io.cpp
    proc_attr_native_bridge.cpp
    avc_lookup_probe.cpp
    avc_lookup_parsers.cpp
    avc_lookup_io.cpp
    app_zygote_timing.cpp
    avc_lookup_native_bridge.cpp
    selinux_status_page_probe.cpp
    selinux_status_abi_probe.cpp
    selinux_status_abi_native_bridge.cpp
)

# The standalone PoC compiles its timing loop at O2, including in Debug builds.
set_source_files_properties(app_zygote_timing.cpp PROPERTIES COMPILE_OPTIONS "-O2")
