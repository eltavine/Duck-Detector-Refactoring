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

#include "selinux/context_validity_probe.h"

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <string>
#include <sys/system_properties.h>
#include <utility>
#include <unistd.h>

namespace duckdetector::selinux {
    namespace {

        constexpr const char *kProcAttrCurrentPath = "/proc/self/attr/current";
        constexpr const char *kSelinuxContextPath = "/sys/fs/selinux/context";
        constexpr const char *kExpectedCarrierType = "app_zygote";
        constexpr const char *kExpectedCarrierPrefix = "u:r:app_zygote:s0";
        constexpr const char *kIsolatedAppContext = "u:r:isolated_app:s0";
        constexpr const char *kKsuContext = "u:r:ksu:s0";
        constexpr const char *kKsuFileContext = "u:object_r:ksu_file:s0";
        constexpr const char *kNegativeControlContext = "u:r:duckdetector_context_oracle_sentinel:s0";
        constexpr const char *kStockFileControlContext = "u:object_r:system_data_file:s0";
        constexpr const char *kNegativeFileControlContext =
                "u:object_r:duckdetector_context_oracle_sentinel_file:s0";
        constexpr const char *kQueryMethod = "raw selinuxfs write";
        constexpr const char *kDirtyPolicyQueryMethod = "android.os.SELinux.checkSELinuxAccess";
        constexpr const char *kProcessClass = "process";
        constexpr const char *kDyntransitionPermission = "dyntransition";
        constexpr const char *kCapabilityClass = "capability";
        constexpr const char *kBinderClass = "binder";
        constexpr const char *kFileClass = "file";
        constexpr const char *kDirClass = "dir";
        constexpr const char *kReadPermission = "read";
        constexpr const char *kCallPermission = "call";
        constexpr const char *kExecmemPermission = "execmem";
        constexpr const char *kTransitionPermission = "transition";
        constexpr const char *kSearchPermission = "search";
        constexpr const char *kSysAdminPermission = "sys_admin";
        constexpr const char *kSystemServerContext = "u:r:system_server:s0";
        constexpr const char *kFsckUntrustedContext = "u:r:fsck_untrusted:s0";
        constexpr const char *kShellContext = "u:r:shell:s0";
        constexpr const char *kSuContext = "u:r:su:s0";
        constexpr const char *kAdbdContext = "u:r:adbd:s0";
        constexpr const char *kAdbrootContext = "u:r:adbroot:s0";
        constexpr const char *kUntrustedAppContext = "u:r:untrusted_app:s0";
        constexpr const char *kMagiskContext = "u:r:magisk:s0";
        constexpr const char *kLsposedFileContext = "u:object_r:lsposed_file:s0";
        constexpr const char *kXposedDataContext = "u:object_r:xposed_data:s0";
        constexpr const char *kZygoteContext = "u:r:zygote:s0";
        constexpr const char *kAdbDataFileContext = "u:object_r:adb_data_file:s0";
        constexpr const char *kDirtyPolicyNegativeControlContext =
                "u:r:duckdetector_dirty_policy_sentinel:s0";

        using IsSelinuxEnabledFn = int (*)();
        using SecurityGetEnforceFn = int (*)();
        using GetConFn = int (*)(char **);
        using GetPidConFn = int (*)(pid_t, char **);
        using GetFileConFn = int (*)(const char *, char **);
        using FreeConFn = void (*)(char *);
        using SelinuxCheckAccessFn = int (*)(
                const char *scon,
                const char *tcon,
                const char *tclass,
                const char *perm,
                void *auditdata
        );

        struct LoadedSelinuxSymbols {
            void *handle = nullptr;
            bool owns_handle = false;
            IsSelinuxEnabledFn is_selinux_enabled = nullptr;
            SecurityGetEnforceFn security_getenforce = nullptr;
            GetConFn getcon = nullptr;
            GetPidConFn getpidcon = nullptr;
            GetFileConFn getfilecon = nullptr;
            FreeConFn freecon = nullptr;
            SelinuxCheckAccessFn check_access = nullptr;
        };

        struct ContextCheckResult {
            std::optional<bool> valid;
            std::string note;
        };

        struct ControlPairResult {
            ContextCheckResult first;
            ContextCheckResult second;
            bool stable = false;
        };

        struct AccessPairResult {
            std::optional<bool> first;
            std::optional<bool> second;
            bool stable = false;
        };

        std::string trim(std::string value) {
            while (!value.empty() &&
                   (value.back() == '\n' || value.back() == '\r' || value.back() == '\0' ||
                    value.back() == ' ' || value.back() == '\t')) {
                value.pop_back();
            }
            while (!value.empty() &&
                   (value.front() == ' ' || value.front() == '\t')) {
                value.erase(value.begin());
            }
            return value;
        }

        template<typename T>
        T resolve_symbol(
                void *handle,
                const char *symbol
        ) {
            return reinterpret_cast<T>(dlsym(handle, symbol));
        }

        LoadedSelinuxSymbols load_selinux_symbols() {
            LoadedSelinuxSymbols symbols;
            symbols.is_selinux_enabled = resolve_symbol<IsSelinuxEnabledFn>(RTLD_DEFAULT,
                                                                            "is_selinux_enabled");
            symbols.security_getenforce = resolve_symbol<SecurityGetEnforceFn>(RTLD_DEFAULT,
                                                                               "security_getenforce");
            symbols.getcon = resolve_symbol<GetConFn>(RTLD_DEFAULT, "getcon");
            symbols.getpidcon = resolve_symbol<GetPidConFn>(RTLD_DEFAULT, "getpidcon");
            symbols.getfilecon = resolve_symbol<GetFileConFn>(RTLD_DEFAULT, "getfilecon");
            symbols.freecon = resolve_symbol<FreeConFn>(RTLD_DEFAULT, "freecon");
            symbols.check_access = resolve_symbol<SelinuxCheckAccessFn>(RTLD_DEFAULT,
                                                                        "selinux_check_access");
            if (symbols.is_selinux_enabled != nullptr &&
                symbols.security_getenforce != nullptr &&
                symbols.getcon != nullptr &&
                symbols.getpidcon != nullptr &&
                symbols.getfilecon != nullptr &&
                symbols.freecon != nullptr &&
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
            symbols.is_selinux_enabled = resolve_symbol<IsSelinuxEnabledFn>(symbols.handle,
                                                                            "is_selinux_enabled");
            symbols.security_getenforce = resolve_symbol<SecurityGetEnforceFn>(symbols.handle,
                                                                               "security_getenforce");
            symbols.getcon = resolve_symbol<GetConFn>(symbols.handle, "getcon");
            symbols.getpidcon = resolve_symbol<GetPidConFn>(symbols.handle, "getpidcon");
            symbols.getfilecon = resolve_symbol<GetFileConFn>(symbols.handle, "getfilecon");
            symbols.freecon = resolve_symbol<FreeConFn>(symbols.handle, "freecon");
            symbols.check_access = resolve_symbol<SelinuxCheckAccessFn>(symbols.handle,
                                                                        "selinux_check_access");
            return symbols;
        }

        std::optional<std::string> call_context_getter(
                const LoadedSelinuxSymbols &symbols,
                int (*getter)(char **)
        ) {
            if (getter == nullptr || symbols.freecon == nullptr) {
                return std::nullopt;
            }
            char *raw = nullptr;
            if (getter(&raw) != 0 || raw == nullptr) {
                if (raw != nullptr) {
                    symbols.freecon(raw);
                }
                return std::nullopt;
            }
            std::string value = trim(raw);
            symbols.freecon(raw);
            return value;
        }

        std::optional<std::string> call_pid_context_getter(
                const LoadedSelinuxSymbols &symbols,
                pid_t pid
        ) {
            if (symbols.getpidcon == nullptr || symbols.freecon == nullptr) {
                return std::nullopt;
            }
            char *raw = nullptr;
            if (symbols.getpidcon(pid, &raw) != 0 || raw == nullptr) {
                if (raw != nullptr) {
                    symbols.freecon(raw);
                }
                return std::nullopt;
            }
            std::string value = trim(raw);
            symbols.freecon(raw);
            return value;
        }

        std::optional<std::string> call_file_context_getter(
                const LoadedSelinuxSymbols &symbols,
                const char *path
        ) {
            if (symbols.getfilecon == nullptr || symbols.freecon == nullptr) {
                return std::nullopt;
            }
            char *raw = nullptr;
            if (symbols.getfilecon(path, &raw) != 0 || raw == nullptr) {
                if (raw != nullptr) {
                    symbols.freecon(raw);
                }
                return std::nullopt;
            }
            std::string value = trim(raw);
            symbols.freecon(raw);
            return value;
        }

        std::string read_process_context() {
            std::ifstream input(kProcAttrCurrentPath);
            if (!input) {
                return {};
            }

            std::string context;
            std::getline(input, context, '\0');
            return trim(std::move(context));
        }

        std::string context_type(const std::string &context) {
            const std::size_t first = context.find(':');
            if (first == std::string::npos) {
                return {};
            }
            const std::size_t second = context.find(':', first + 1);
            if (second == std::string::npos) {
                return {};
            }
            const std::size_t third = context.find(':', second + 1);
            if (third == std::string::npos) {
                return context.substr(second + 1);
            }
            return context.substr(second + 1, third - second - 1);
        }

        void append_note(ContextValidityProbeSnapshot &snapshot, std::string note) {
            if (!note.empty()) {
                snapshot.notes.push_back(std::move(note));
            }
        }

        void append_boolean_note(
                ContextValidityProbeSnapshot &snapshot,
                const char *label,
                const std::optional<bool> &value
        ) {
            if (!value.has_value()) {
                append_note(snapshot, std::string(label) + "=unavailable");
                return;
            }
            append_note(snapshot, std::string(label) + (*value ? "=yes" : "=no"));
        }

        bool stable_result(
                const ContextCheckResult &first,
                const ContextCheckResult &second
        ) {
            return first.valid.has_value() == second.valid.has_value() &&
                   (!first.valid.has_value() || *first.valid == *second.valid);
        }

        ContextCheckResult check_context_validity(const char *context);

        bool pair_matches_expected(
                const ControlPairResult &pair,
                const bool expected_valid
        ) {
            return pair.stable &&
                   pair.first.valid.has_value() &&
                   *pair.first.valid == expected_valid;
        }

        std::optional<bool> pair_valid_value(const ControlPairResult &pair) {
            if (!pair_matches_expected(pair, true) && !pair_matches_expected(pair, false)) {
                return std::nullopt;
            }
            return pair.first.valid;
        }

        std::optional<bool> pair_rejected_value(const ControlPairResult &pair) {
            if (!pair.stable || !pair.first.valid.has_value()) {
                return std::nullopt;
            }
            return !*pair.first.valid;
        }

        std::optional<bool> pair_allowed_value(const AccessPairResult &pair) {
            if (!pair.stable || !pair.first.has_value()) {
                return std::nullopt;
            }
            return pair.first;
        }

        ControlPairResult check_context_pair_validity(const char *context) {
            ControlPairResult result;
            result.first = check_context_validity(context);
            result.second = check_context_validity(context);
            result.stable = stable_result(result.first, result.second);
            return result;
        }

        std::optional<bool> check_access_rule(
                const LoadedSelinuxSymbols &symbols,
                const char *source,
                const char *target,
                const char *target_class,
                const char *permission
        ) {
            if (symbols.check_access == nullptr) {
                return std::nullopt;
            }
            errno = 0;
            const int result = symbols.check_access(source, target, target_class, permission, nullptr);
            if (result == 0) {
                return true;
            }
            if (errno == EACCES || errno == EPERM) {
                return false;
            }
            return std::nullopt;
        }

        AccessPairResult check_access_rule_pair(
                const LoadedSelinuxSymbols &symbols,
                const char *source,
                const char *target,
                const char *target_class,
                const char *permission
        ) {
            AccessPairResult result;
            result.first = check_access_rule(symbols, source, target, target_class, permission);
            result.second = check_access_rule(symbols, source, target, target_class, permission);
            result.stable = result.first.has_value() == result.second.has_value() &&
                            (!result.first.has_value() || *result.first == *result.second);
            return result;
        }

        void append_access_note(
                DirtyPolicyProbeSnapshot &snapshot,
                const char *label,
                const AccessPairResult &result
        ) {
            std::string line(label);
            line += '=';
            if (result.first.has_value()) {
                line += *result.first ? "allowed" : "denied";
            } else {
                line += "unavailable";
            }
            if (!result.stable) {
                line += " (unstable)";
            }
            snapshot.notes.push_back(std::move(line));
        }

        bool is_user_build() {
            char value[PROP_VALUE_MAX] = {};
            if (__system_property_get("ro.build.type", value) > 0) {
                return std::strcmp(value, "user") == 0;
            }
            return false;
        }

        DirtyPolicyProbeSnapshot collect_dirty_policy_snapshot(
                const LoadedSelinuxSymbols &symbols,
                const std::string &carrier_context,
                const bool carrier_matches_expected,
                const std::optional<bool> &dyntransition_check_passed
        ) {
            DirtyPolicyProbeSnapshot snapshot;
            snapshot.query_method = kDirtyPolicyQueryMethod;
            snapshot.available = symbols.check_access != nullptr;
            snapshot.carrier_context = carrier_context;
            snapshot.carrier_matches_expected = carrier_matches_expected;
            snapshot.notes.push_back(std::string("Carrier context: ") + carrier_context);
            snapshot.notes.push_back(std::string("Query method: ") + kDirtyPolicyQueryMethod);

            if (!snapshot.available) {
                snapshot.failure_reason = "selinux_check_access unavailable from the current carrier.";
                return snapshot;
            }
            if (!carrier_matches_expected || carrier_context.rfind(kExpectedCarrierPrefix, 0) != 0) {
                snapshot.failure_reason = "Carrier context is not app_zygote.";
                snapshot.notes.push_back("Dirty policy access checks require the dedicated app_zygote carrier.");
                return snapshot;
            }
            if (dyntransition_check_passed.has_value() && !*dyntransition_check_passed) {
                snapshot.failure_reason = "app_zygote dyntransition self-check failed.";
                snapshot.notes.push_back("Dirty policy access checks were skipped because the carrier could not confirm app_zygote -> isolated_app dyntransition.");
                return snapshot;
            }

            snapshot.probe_attempted = true;

            const AccessPairResult access_control = check_access_rule_pair(
                    symbols,
                    kExpectedCarrierPrefix,
                    kIsolatedAppContext,
                    kProcessClass,
                    kDyntransitionPermission
            );
            const AccessPairResult negative_control = check_access_rule_pair(
                    symbols,
                    kUntrustedAppContext,
                    kDirtyPolicyNegativeControlContext,
                    kBinderClass,
                    kCallPermission
            );

            snapshot.access_control_allowed = pair_allowed_value(access_control);
            if (const auto negative_allowed = pair_allowed_value(negative_control); negative_allowed.has_value()) {
                snapshot.negative_control_rejected = !*negative_allowed;
            }
            snapshot.controls_passed = access_control.stable && negative_control.stable &&
                                       access_control.first == std::optional<bool>(true) &&
                                       negative_control.first == std::optional<bool>(false);
            snapshot.stable = access_control.stable && negative_control.stable;

            append_access_note(snapshot, "Access control", access_control);
            append_access_note(snapshot, "Negative control", negative_control);

            const AccessPairResult system_server_execmem = check_access_rule_pair(symbols, kSystemServerContext, kSystemServerContext, kProcessClass, kExecmemPermission);
            const AccessPairResult fsck_sys_admin = check_access_rule_pair(symbols, kFsckUntrustedContext, kFsckUntrustedContext, kCapabilityClass, kSysAdminPermission);
            const AccessPairResult shell_su_transition = check_access_rule_pair(symbols, kShellContext, kSuContext, kProcessClass, kTransitionPermission);
            const AccessPairResult adbd_adbroot_binder_call = check_access_rule_pair(symbols, kAdbdContext, kAdbrootContext, kBinderClass, kCallPermission);
            const AccessPairResult magisk_binder_call = check_access_rule_pair(symbols, kUntrustedAppContext, kMagiskContext, kBinderClass, kCallPermission);
            const AccessPairResult ksu_file_read = check_access_rule_pair(symbols, kUntrustedAppContext, kKsuFileContext, kFileClass, kReadPermission);
            const AccessPairResult lsposed_file_read = check_access_rule_pair(symbols, kUntrustedAppContext, kLsposedFileContext, kFileClass, kReadPermission);
            const AccessPairResult xposed_data_file_read = check_access_rule_pair(symbols, kUntrustedAppContext, kXposedDataContext, kFileClass, kReadPermission);
            const AccessPairResult zygote_adb_data_search = check_access_rule_pair(symbols, kZygoteContext, kAdbDataFileContext, kDirClass, kSearchPermission);

            snapshot.system_server_execmem_allowed = pair_allowed_value(system_server_execmem);
            snapshot.fsck_sys_admin_allowed = pair_allowed_value(fsck_sys_admin);
            if (is_user_build()) {
                snapshot.shell_su_transition_allowed = pair_allowed_value(shell_su_transition);
            }
            snapshot.adbd_adbroot_binder_call_allowed = pair_allowed_value(adbd_adbroot_binder_call);
            snapshot.magisk_binder_call_allowed = pair_allowed_value(magisk_binder_call);
            snapshot.ksu_file_read_allowed = pair_allowed_value(ksu_file_read);
            snapshot.lsposed_file_read_allowed = pair_allowed_value(lsposed_file_read);
            snapshot.xposed_data_file_read_allowed = pair_allowed_value(xposed_data_file_read);
            snapshot.zygote_adb_data_search_allowed = pair_allowed_value(zygote_adb_data_search);

            snapshot.stable = snapshot.stable &&
                              system_server_execmem.stable &&
                              fsck_sys_admin.stable &&
                              adbd_adbroot_binder_call.stable &&
                              magisk_binder_call.stable &&
                              ksu_file_read.stable &&
                              lsposed_file_read.stable &&
                              xposed_data_file_read.stable &&
                              zygote_adb_data_search.stable &&
                              (!is_user_build() || shell_su_transition.stable);

            append_access_note(snapshot, "system_server execmem", system_server_execmem);
            append_access_note(snapshot, "fsck_untrusted sys_admin", fsck_sys_admin);
            if (is_user_build()) {
                append_access_note(snapshot, "shell -> su transition", shell_su_transition);
            } else {
                snapshot.notes.push_back("shell -> su transition skipped because ro.build.type is not user.");
            }
            append_access_note(snapshot, "adbd -> adbroot binder", adbd_adbroot_binder_call);
            append_access_note(snapshot, "untrusted_app -> magisk binder", magisk_binder_call);
            append_access_note(snapshot, "untrusted_app -> ksu_file read", ksu_file_read);
            append_access_note(snapshot, "untrusted_app -> lsposed_file read", lsposed_file_read);
            append_access_note(snapshot, "untrusted_app -> xposed_data read", xposed_data_file_read);
            append_access_note(snapshot, "zygote -> adb_data_file search", zygote_adb_data_search);

            if (!snapshot.stable) {
                snapshot.failure_reason = "Dirty policy oracle repeated inconsistently.";
            } else if (!snapshot.controls_passed) {
                snapshot.failure_reason = "Dirty policy oracle self-test failed.";
            }
            return snapshot;
        }

        void append_repeat_note(
                ContextValidityProbeSnapshot &snapshot,
                const char *label,
                const ContextCheckResult &result
        ) {
            std::string line(label);
            line += '=';
            if (result.valid.has_value()) {
                line += *result.valid ? "valid" : "invalid";
            } else {
                line += "unavailable";
            }
            if (!result.note.empty()) {
                line += " (";
                line += result.note;
                line += ')';
            }
            append_note(snapshot, std::move(line));
        }

        ContextCheckResult check_context_validity(const char *context) {
            ContextCheckResult result;

            int fd = open(kSelinuxContextPath, O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                const int error = errno;
                if (error == EINVAL) {
                    result.valid = false;
                    result.note = std::string("Invalid context: ") + context +
                                  " errno=" + std::to_string(error);
                } else {
                    result.note = std::string("Unavailable: ") + context +
                                  " errno=" + std::to_string(error);
                }
                return result;
            }

            const ssize_t written = write(fd, context, std::strlen(context) + 1);
            const int error = errno;
            close(fd);

            if (written >= 0) {
                result.valid = true;
                return result;
            }

            if (error == EINVAL) {
                result.valid = false;
                result.note = std::string("Invalid context: ") + context +
                              " errno=" + std::to_string(error);
            } else {
                result.note = std::string("Unavailable: ") + context +
                              " errno=" + std::to_string(error);
            }
            return result;
        }

    }  // namespace

    ContextValidityProbeSnapshot collect_context_validity_snapshot() {
        ContextValidityProbeSnapshot snapshot;
        snapshot.query_method = kQueryMethod;
        const LoadedSelinuxSymbols symbols = load_selinux_symbols();
        if (symbols.is_selinux_enabled != nullptr) {
            snapshot.selinux_enabled = symbols.is_selinux_enabled() == 1;
        }
        if (symbols.security_getenforce != nullptr) {
            const int enforce = symbols.security_getenforce();
            if (enforce == 0 || enforce == 1) {
                snapshot.selinux_enforced = enforce == 1;
            }
        }

        const std::string carrier_context = read_process_context();
        if (carrier_context.empty()) {
            snapshot.failure_reason = "Current process SELinux context unreadable.";
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.available = true;
        snapshot.carrier_context = carrier_context;
        snapshot.carrier_matches_expected = context_type(carrier_context) == kExpectedCarrierType;
        append_note(snapshot, std::string("Carrier context: ") + carrier_context);
        append_note(snapshot, std::string("Expected carrier type: ") + kExpectedCarrierType);

        if (const auto current_context = call_context_getter(symbols, symbols.getcon);
            current_context.has_value()) {
            snapshot.pid_context_matches_current = (*current_context == carrier_context);
        }
        if (const auto pid_context = call_pid_context_getter(symbols, getpid());
            pid_context.has_value()) {
            snapshot.pid_context_matches_current = (*pid_context == carrier_context);
        }
        if (const auto proc_self_context = call_file_context_getter(symbols, "/proc/self");
            proc_self_context.has_value()) {
            snapshot.proc_self_context_matches_current = (*proc_self_context == carrier_context);
        }
        if (symbols.check_access != nullptr) {
            const int check = symbols.check_access(
                    kExpectedCarrierPrefix,
                    kIsolatedAppContext,
                    kProcessClass,
                    kDyntransitionPermission,
                    nullptr
            );
            snapshot.dyntransition_check_passed = check == 0;
        }
        snapshot.dirty_policy = collect_dirty_policy_snapshot(
                symbols,
                carrier_context,
                snapshot.carrier_matches_expected,
                snapshot.dyntransition_check_passed
        );

        if (!snapshot.carrier_matches_expected ||
            carrier_context.rfind(kExpectedCarrierPrefix, 0) != 0) {
            snapshot.failure_reason = "Carrier context is not app_zygote.";
            append_note(snapshot, "The oracle is only meaningful from an app_zygote carrier.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.selinux_enabled.has_value() && !*snapshot.selinux_enabled) {
            snapshot.failure_reason = "SELinux is disabled.";
            append_note(snapshot, "The carrier reported SELinux disabled.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.selinux_enforced.has_value() && !*snapshot.selinux_enforced) {
            snapshot.failure_reason = "SELinux is permissive.";
            append_note(snapshot, "The carrier reported permissive SELinux.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.pid_context_matches_current.has_value() &&
            !*snapshot.pid_context_matches_current) {
            snapshot.failure_reason = "PID context mismatch.";
            append_note(snapshot, "The carrier pid context did not match /proc/self/attr/current.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.proc_self_context_matches_current.has_value() &&
            !*snapshot.proc_self_context_matches_current) {
            snapshot.failure_reason = "/proc/self context mismatch.";
            append_note(snapshot,
                        "The carrier /proc/self file context did not match /proc/self/attr/current.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }
        if (snapshot.dyntransition_check_passed.has_value() &&
            !*snapshot.dyntransition_check_passed) {
            snapshot.failure_reason = "app_zygote dyntransition self-check failed.";
            append_note(snapshot,
                        "The carrier could not confirm app_zygote -> isolated_app dyntransition.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.probe_attempted = true;

        const ControlPairResult carrier_control = check_context_pair_validity(carrier_context.c_str());
        const ControlPairResult negative_control = check_context_pair_validity(kNegativeControlContext);
        const ControlPairResult file_control = check_context_pair_validity(kStockFileControlContext);
        const ControlPairResult negative_file_control =
                check_context_pair_validity(kNegativeFileControlContext);

        snapshot.carrier_control_valid = pair_valid_value(carrier_control);
        snapshot.negative_control_rejected = pair_rejected_value(negative_control);
        snapshot.file_control_valid = pair_valid_value(file_control);
        snapshot.file_negative_control_rejected = pair_rejected_value(negative_file_control);
        snapshot.oracle_controls_passed =
                pair_matches_expected(carrier_control, true) &&
                pair_matches_expected(negative_control, false) &&
                pair_matches_expected(file_control, true) &&
                pair_matches_expected(negative_file_control, false);

        append_note(snapshot, std::string("Query method: ") + kQueryMethod);
        append_note(snapshot, std::string("Positive control context: ") + carrier_context);
        append_note(snapshot, std::string("Negative control context: ") + kNegativeControlContext);
        append_note(snapshot, std::string("File control context: ") + kStockFileControlContext);
        append_note(snapshot,
                    std::string("File negative control context: ") + kNegativeFileControlContext);
        append_note(snapshot, carrier_control.first.note);
        append_note(snapshot, negative_control.first.note);
        append_note(snapshot, file_control.first.note);
        append_note(snapshot, negative_file_control.first.note);
        if (!carrier_control.stable) {
            append_note(snapshot, "Carrier control repeated inconsistently.");
        }
        if (!negative_control.stable) {
            append_note(snapshot, "Negative control repeated inconsistently.");
        }
        if (!file_control.stable) {
            append_note(snapshot, "File control repeated inconsistently.");
        }
        if (!negative_file_control.stable) {
            append_note(snapshot, "File negative control repeated inconsistently.");
        }
        append_boolean_note(snapshot, "Carrier control valid", snapshot.carrier_control_valid);
        append_boolean_note(snapshot, "Negative control rejected", snapshot.negative_control_rejected);
        append_boolean_note(snapshot, "File control valid", snapshot.file_control_valid);
        append_boolean_note(snapshot,
                            "File negative control rejected",
                            snapshot.file_negative_control_rejected);

        if (!snapshot.oracle_controls_passed) {
            snapshot.failure_reason = "Context validity oracle self-test failed.";
            append_note(snapshot,
                        "KSU-specific context queries were skipped to avoid interpreting an untrusted oracle.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        const ContextCheckResult domain_first = check_context_validity(kKsuContext);
        const ContextCheckResult domain_second = check_context_validity(kKsuContext);
        const ContextCheckResult file_first = check_context_validity(kKsuFileContext);
        const ContextCheckResult file_second = check_context_validity(kKsuFileContext);

        const bool domain_stable = stable_result(domain_first, domain_second);
        const bool file_stable = stable_result(file_first, file_second);
        snapshot.ksu_results_stable = domain_stable && file_stable;

        append_repeat_note(snapshot, "Domain repeat 1", domain_first);
        append_repeat_note(snapshot, "Domain repeat 2", domain_second);
        append_repeat_note(snapshot, "File repeat 1", file_first);
        append_repeat_note(snapshot, "File repeat 2", file_second);

        if (!snapshot.ksu_results_stable) {
            snapshot.failure_reason = "Context validity oracle repeatability failed.";
            append_note(snapshot,
                        "The KSU-specific context verdict changed across repeated writes, so it was not trusted.");
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        const ContextCheckResult domain_result = domain_first;
        const ContextCheckResult file_result = file_first;

        snapshot.ksu_domain_valid = domain_result.valid;
        snapshot.ksu_file_valid = file_result.valid;
        append_note(snapshot, domain_result.note);
        append_note(snapshot, file_result.note);

        if (domain_result.valid.has_value() && file_result.valid.has_value()) {
            snapshot.bit_pair.push_back(*domain_result.valid ? '1' : '0');
            snapshot.bit_pair.push_back(*file_result.valid ? '1' : '0');
            if (*domain_result.valid && *file_result.valid) {
                append_note(snapshot, "Both KSU-specific contexts were accepted by live policy.");
            } else if (!*domain_result.valid && !*file_result.valid) {
                append_note(snapshot, "Neither KSU-specific context was accepted by live policy.");
            } else {
                append_note(snapshot,
                            "Split verdict: one KSU-specific context was accepted while the other was not.");
            }
            if (symbols.owns_handle && symbols.handle != nullptr) {
                dlclose(symbols.handle);
            }
            return snapshot;
        }

        snapshot.failure_reason = "Context validity probe could not complete both checks.";
        if (!domain_result.valid.has_value() || !file_result.valid.has_value()) {
            append_note(snapshot,
                        "At least one KSU context write was unavailable from the current carrier.");
        }
        if (symbols.owns_handle && symbols.handle != nullptr) {
            dlclose(symbols.handle);
        }
        return snapshot;
    }

}  // namespace duckdetector::selinux
