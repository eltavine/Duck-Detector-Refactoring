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

#include <jni.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fcntl.h>
#include <regex>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

    struct CmdlineCheck {
        const char *pattern;
        const char *description;
        bool critical;
    };

    struct KernelSnapshot {
        bool available = true;
        std::string proc_version;
        std::string proc_cmdline;
        bool suspicious_cmdline = false;
        bool build_time_mismatch = false;
        bool kptr_exposed = false;
        std::vector<std::string> findings;
    };

    constexpr CmdlineCheck kCmdlineChecks[] = {
            {"androidboot.verifiedbootstate=orange",     "Bootloader unlocked (orange)",   true},
            {"androidboot.verifiedbootstate=yellow",     "Self-signed boot (yellow)",      true},
            {"androidboot.enable_dm_verity=0",           "dm-verity disabled",             true},
            {"androidboot.secboot=disabled",             "Secure boot disabled",           true},
            {"androidboot.vbmeta.device_state=unlocked", "vbmeta unlocked",                true},
            {"skip_initramfs",                           "Skip initramfs (possible root)", false},
            {"init=/sbin",                               "Custom init path",               true},
            {"init=/system",                             "Custom init path",               false},
            {"androidboot.force_normal_boot=1",          "Force normal boot",              false},
            {"magisk",                                   "Magisk reference in cmdline",    true},
            {"ksu",                                      "KernelSU reference in cmdline",  true},
            {"apatch",                                   "APatch reference in cmdline",    true},
            {"rootfs=",                                  "Custom rootfs",                  false},
            {"androidboot.slot_suffix=",                 "Slot suffix present",            false},
    };

    int month_to_number(const std::string &month) {
        static const char *months[] = {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        };
        for (int i = 0; i < 12; ++i) {
            if (month == months[i]) {
                return i;
            }
        }
        return -1;
    }

    std::string lowercase_copy(std::string value) {
        for (char &ch: value) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    bool contains_ignore_case(const std::string &input, const std::string &needle) {
        return lowercase_copy(input).find(lowercase_copy(needle)) != std::string::npos;
    }

    std::string escape_value(std::string value) {
        for (char &ch: value) {
            if (ch == '\0') {
                ch = ' ';
            }
        }

        std::string escaped;
        escaped.reserve(value.size());
        for (char ch: value) {
            switch (ch) {
                case '\n':
                    escaped += "\\n";
                    break;
                case '\r':
                    escaped += "\\r";
                    break;
                default:
                    escaped += ch;
                    break;
            }
        }
        return escaped;
    }

    std::string read_file_via_syscall(const char *path, size_t max_bytes = 16384) {
        const int fd = static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC,
                                                0));
        if (fd < 0) {
            return "";
        }

        std::string content;
        content.reserve(4096);
        char buffer[4096];
        ssize_t bytes_read = 0;
        while ((bytes_read = syscall(__NR_read, fd, buffer, sizeof(buffer))) > 0) {
            content.append(buffer, static_cast<size_t>(bytes_read));
            if (content.size() >= max_bytes) {
                break;
            }
        }

        syscall(__NR_close, fd);

        while (!content.empty() &&
               (content.back() == '\n' || content.back() == '\r' || content.back() == '\0')) {
            content.pop_back();
        }
        return content;
    }

    void read_proc_files(KernelSnapshot &snapshot) {
        snapshot.proc_version = read_file_via_syscall("/proc/version", 8192);
        snapshot.proc_cmdline = read_file_via_syscall("/proc/cmdline", 8192);

        if (snapshot.proc_version.empty()) {
            snapshot.findings.emplace_back("PROC_VERSION|FAILED|Unable to read /proc/version");
        }
        if (snapshot.proc_cmdline.empty()) {
            snapshot.findings.emplace_back("PROC_CMDLINE|FAILED|Unable to read /proc/cmdline");
        }
    }

    void check_cmdline(KernelSnapshot &snapshot) {
        if (snapshot.proc_cmdline.empty()) {
            return;
        }
        for (const auto &check: kCmdlineChecks) {
            if (contains_ignore_case(snapshot.proc_cmdline, check.pattern)) {
                snapshot.suspicious_cmdline = snapshot.suspicious_cmdline || check.critical;
                const char *severity = check.critical ? "CRITICAL" : "INFO";
                snapshot.findings.emplace_back(
                        std::string("CMDLINE|") + severity + "|" + check.description);
            }
        }

        const std::string verified_prefix = "androidboot.verifiedbootstate=";
        const size_t verified_pos = snapshot.proc_cmdline.find(verified_prefix);
        if (verified_pos != std::string::npos) {
            const size_t value_start = verified_pos + verified_prefix.size();
            size_t value_end = snapshot.proc_cmdline.find_first_of(" \t\n", value_start);
            if (value_end == std::string::npos) {
                value_end = snapshot.proc_cmdline.size();
            }
            const std::string state = snapshot.proc_cmdline.substr(value_start,
                                                                   value_end - value_start);
            if (state == "green") {
                snapshot.findings.emplace_back("CMDLINE|GOOD|verifiedbootstate=green (verified)");
            }
        }
    }

    void check_build_time(KernelSnapshot &snapshot, jlong system_build_time) {
        if (snapshot.proc_version.empty() || system_build_time <= 0) {
            return;
        }

        const std::regex date_pattern(
                R"((\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\w+\s+(\d{4}))");
        std::smatch match;
        if (!std::regex_search(snapshot.proc_version, match, date_pattern)) {
            return;
        }

        const int month = month_to_number(match[2].str());
        if (month < 0) {
            return;
        }

        std::tm kernel_tm = {};
        kernel_tm.tm_year = std::stoi(match[7].str()) - 1900;
        kernel_tm.tm_mon = month;
        kernel_tm.tm_mday = std::stoi(match[3].str());
        kernel_tm.tm_hour = std::stoi(match[4].str());
        kernel_tm.tm_min = std::stoi(match[5].str());
        kernel_tm.tm_sec = std::stoi(match[6].str());

        const time_t kernel_time = mktime(&kernel_tm);
        const time_t system_time = static_cast<time_t>(system_build_time / 1000);
        const double diff_days = difftime(kernel_time, system_time) / (24 * 60 * 60);
        if (diff_days <= 30 && diff_days >= -365) {
            snapshot.findings.emplace_back("BUILD_TIME|OK|Build times are consistent");
            return;
        }

        snapshot.build_time_mismatch = true;

        char kernel_date[32];
        char system_date[32];
        strftime(kernel_date, sizeof(kernel_date), "%Y-%m-%d", &kernel_tm);
        std::tm *system_tm = localtime(&system_time);
        if (system_tm == nullptr) {
            return;
        }
        strftime(system_date, sizeof(system_date), "%Y-%m-%d", system_tm);

        std::ostringstream finding;
        finding << "BUILD_TIME|MISMATCH|Kernel: " << kernel_date
                << ", System: " << system_date
                << " (diff: " << static_cast<int>(diff_days) << " days)";
        snapshot.findings.push_back(finding.str());
    }

    void check_kptr(KernelSnapshot &snapshot) {
        const std::string kallsyms = read_file_via_syscall("/proc/kallsyms", 16384);
        if (kallsyms.empty()) {
            snapshot.findings.emplace_back("KPTR_RESTRICT|UNKNOWN|Cannot read /proc/kallsyms");
            return;
        }

        std::istringstream stream(kallsyms);
        std::string line;
        int line_count = 0;
        int non_zero_count = 0;
        while (std::getline(stream, line) && line_count < 20) {
            ++line_count;
            if (line.size() < 16) {
                continue;
            }
            const std::string address = line.substr(0, 16);
            bool has_non_zero = false;
            for (char ch: address) {
                if (ch != '0' && ch != ' ') {
                    has_non_zero = true;
                    break;
                }
            }
            if (has_non_zero) {
                ++non_zero_count;
            }
        }

        if (line_count > 0 && non_zero_count > line_count / 2) {
            snapshot.kptr_exposed = true;
            std::ostringstream finding;
            finding << "KPTR_RESTRICT|DISABLED|Kernel addresses exposed ("
                    << non_zero_count << "/" << line_count << " non-zero)";
            snapshot.findings.push_back(finding.str());
        } else {
            snapshot.findings.emplace_back("KPTR_RESTRICT|ENABLED|Kernel addresses hidden");
        }
    }

    KernelSnapshot collect_snapshot(jlong system_build_time) {
        KernelSnapshot snapshot;
        read_proc_files(snapshot);
        check_cmdline(snapshot);
        check_build_time(snapshot, system_build_time);
        check_kptr(snapshot);
        return snapshot;
    }

    jstring to_jstring(JNIEnv *env, const std::string &value) {
        return env->NewStringUTF(value.c_str());
    }

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_features_kernelcheck_data_native_KernelCheckNativeBridge_nativeCollectSnapshot(
        JNIEnv *env,
        jobject /* this */,
        jlong system_build_time
) {
    const KernelSnapshot snapshot = collect_snapshot(system_build_time);

    std::ostringstream output;
    output << "AVAILABLE=" << (snapshot.available ? "1" : "0") << "\n";
    output << "PROC_VERSION=" << escape_value(snapshot.proc_version) << "\n";
    output << "PROC_CMDLINE=" << escape_value(snapshot.proc_cmdline) << "\n";
    output << "CMDLINE=" << (snapshot.suspicious_cmdline ? "1" : "0") << "\n";
    output << "BUILD_TIME=" << (snapshot.build_time_mismatch ? "1" : "0") << "\n";
    output << "KPTR=" << (snapshot.kptr_exposed ? "1" : "0") << "\n";

    for (const std::string &finding: snapshot.findings) {
        output << "FINDING=" << escape_value(finding) << "\n";
    }

    return to_jstring(env, output.str());
}
