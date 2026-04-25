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

#include "selinux/audit_probe.h"

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>
#include <unistd.h>

namespace duckdetector::selinux {
    namespace {

        constexpr int kSelinuxCbLog = 0;
        constexpr int kSelinuxCbAudit = 1;
        constexpr const char *kProcAttrCurrentPath = "/proc/self/attr/current";
        constexpr const char *kProbeMarkerPrefix = "duckdetector_probe=";

        using security_class_t = unsigned short;

        union selinux_callback {
            int (*func_log)(int type, const char *fmt, ...);

            int
            (*func_audit)(void *auditdata, security_class_t cls, char *msgbuf, size_t msgbufsize);

            void *raw;
        };

        using SelinuxSetCallbackFn = void (*)(int type, selinux_callback callback);
        using SelinuxGetCallbackFn = selinux_callback (*)(int type);
        using SelinuxCheckAccessFn = int (*)(
                const char *scon,
                const char *tcon,
                const char *tclass,
                const char *perm,
                void *auditdata
        );

        struct LoadedSymbols {
            void *handle = nullptr;
            bool owns_handle = false;
            SelinuxSetCallbackFn set_callback = nullptr;
            SelinuxGetCallbackFn get_callback = nullptr;
            SelinuxCheckAccessFn check_access = nullptr;
        };

        struct ProbeSpec {
            const char *tcontext;
            const char *tclass_name;
            const char *permission;
        };

        const ProbeSpec kProbeSpecs[] = {
                {
                        "u:object_r:system_file:s0",
                        "file",
                        "write",
                },
                {
                        "u:r:init:s0",
                        "process",
                        "ptrace",
                },
        };

        std::mutex g_capture_mutex;
        std::vector<std::string> *g_active_capture_lines = nullptr;
        std::atomic<unsigned int> g_probe_counter{0};

        std::string trim(std::string value) {
            value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
            while (!value.empty() &&
                   (value.back() == '\n' || value.back() == '\r' || value.back() == ' ')) {
                value.pop_back();
            }
            const auto first_non_space = value.find_first_not_of(' ');
            if (first_non_space == std::string::npos) {
                return {};
            }
            if (first_non_space > 0) {
                value.erase(0, first_non_space);
            }
            return value;
        }

        std::string read_process_context() {
            std::ifstream input(kProcAttrCurrentPath);
            if (!input) {
                return {};
            }
            std::string context;
            std::getline(input, context, '\0');
            return trim(context);
        }

        int capture_log_callback(
                int,
                const char *fmt,
                ...
        ) {
            if (fmt == nullptr) {
                return 0;
            }

            va_list args;
            va_start(args, fmt);
            va_list copied_args;
            va_copy(copied_args, args);
            const int required = std::vsnprintf(nullptr, 0, fmt, copied_args);
            va_end(copied_args);

            if (required < 0) {
                va_end(args);
                return 0;
            }

            std::string buffer(static_cast<size_t>(required) + 1, '\0');
            std::vsnprintf(buffer.data(), buffer.size(), fmt, args);
            va_end(args);
            buffer.resize(static_cast<size_t>(required));
            buffer = trim(std::move(buffer));
            if (buffer.empty()) {
                return 0;
            }

            std::lock_guard<std::mutex> lock(g_capture_mutex);
            if (g_active_capture_lines != nullptr) {
                g_active_capture_lines->push_back(buffer);
            }
            return 0;
        }

        int capture_audit_callback(
                void *auditdata,
                security_class_t,
                char *msgbuf,
                size_t msgbufsize
        ) {
            const char *marker =
                    auditdata != nullptr ? static_cast<const char *>(auditdata) : "missing";
            return std::snprintf(msgbuf, msgbufsize, "%s%s", kProbeMarkerPrefix, marker);
        }

        std::string make_probe_marker() {
            return "ddprobe_" + std::to_string(getpid()) + "_" + std::to_string(++g_probe_counter);
        }

        template<typename T>
        T resolve_symbol(
                void *handle,
                const char *symbol
        ) {
            return reinterpret_cast<T>(dlsym(handle, symbol));
        }

        LoadedSymbols load_symbols() {
            LoadedSymbols symbols;

            symbols.set_callback = resolve_symbol<SelinuxSetCallbackFn>(RTLD_DEFAULT,
                                                                        "selinux_set_callback");
            symbols.get_callback = resolve_symbol<SelinuxGetCallbackFn>(RTLD_DEFAULT,
                                                                        "selinux_get_callback");
            symbols.check_access = resolve_symbol<SelinuxCheckAccessFn>(RTLD_DEFAULT,
                                                                        "selinux_check_access");
            if (symbols.set_callback != nullptr &&
                symbols.get_callback != nullptr &&
                symbols.check_access != nullptr) {
                return symbols;
            }

#ifdef RTLD_NOLOAD
            symbols.handle = dlopen("libselinux.so", RTLD_NOW | RTLD_NOLOAD);
#else
            symbols.handle = nullptr;
#endif
            if (symbols.handle == nullptr) {
                return symbols;
            }

            symbols.owns_handle = true;
            symbols.set_callback = resolve_symbol<SelinuxSetCallbackFn>(symbols.handle,
                                                                        "selinux_set_callback");
            symbols.get_callback = resolve_symbol<SelinuxGetCallbackFn>(symbols.handle,
                                                                        "selinux_get_callback");
            symbols.check_access = resolve_symbol<SelinuxCheckAccessFn>(symbols.handle,
                                                                        "selinux_check_access");
            return symbols;
        }

    }  // namespace

    AuditProbeSnapshot collect_audit_snapshot() {
        AuditProbeSnapshot snapshot;
        const LoadedSymbols symbols = load_symbols();
        if (symbols.set_callback == nullptr ||
            symbols.get_callback == nullptr ||
            symbols.check_access == nullptr) {
            snapshot.failure_reason = "libselinux callback symbols unavailable in this app process.";
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.available = true;
        const std::string source_context = read_process_context();
        if (source_context.empty()) {
            snapshot.failure_reason = "Current process SELinux context unreadable.";
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        const selinux_callback previous_callback = symbols.get_callback(kSelinuxCbLog);
        const selinux_callback previous_audit_callback = symbols.get_callback(kSelinuxCbAudit);
        selinux_callback callback{};
        callback.func_log = capture_log_callback;
        selinux_callback audit_callback{};
        audit_callback.func_audit = capture_audit_callback;
        snapshot.probe_marker = make_probe_marker();

        {
            std::lock_guard<std::mutex> lock(g_capture_mutex);
            g_active_capture_lines = &snapshot.callback_lines;
        }

        symbols.set_callback(kSelinuxCbLog, callback);
        symbols.set_callback(kSelinuxCbAudit, audit_callback);
        snapshot.callback_installed = true;

        for (const ProbeSpec &spec: kProbeSpecs) {
            snapshot.probe_ran = true;
            const int result = symbols.check_access(
                    source_context.c_str(),
                    spec.tcontext,
                    spec.tclass_name,
                    spec.permission,
                    snapshot.probe_marker.data()
            );
            if (result == 0) {
                snapshot.allow_observed = true;
            } else {
                snapshot.denial_observed = true;
            }
        }

        symbols.set_callback(kSelinuxCbLog, previous_callback);
        symbols.set_callback(kSelinuxCbAudit, previous_audit_callback);
        {
            std::lock_guard<std::mutex> lock(g_capture_mutex);
            g_active_capture_lines = nullptr;
        }

        if (!snapshot.allow_observed &&
            !snapshot.denial_observed &&
            snapshot.callback_lines.empty() &&
            snapshot.failure_reason.empty()) {
            snapshot.failure_reason = "Controlled libselinux access checks produced no observable result.";
        }

        if (symbols.owns_handle && symbols.handle != nullptr) {
            dlclose(symbols.handle);
        }
        return snapshot;
    }

}  // namespace duckdetector::selinux
