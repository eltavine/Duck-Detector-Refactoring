/*
 * Copyright 2026 Duck Apps Contributor
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 */

// /sys/fs/selinux/access ignored-fourth-field experiment.
// ACK 5.15 sel_write_access uses sscanf("%s %s %hu") and ignores the tail.
// Some SELinux Hide hooks instead inspect the entire transaction input.
// This only computes an access vector; it never changes a SID or policy.
#include <jni.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr char kAccess[] = "/sys/fs/selinux/access";
constexpr char kCurrent[] = "/proc/thread-self/attr/current";
constexpr char kEnforce[] = "/sys/fs/selinux/enforce";
constexpr char kClass[] = "/sys/fs/selinux/class/process/index";
constexpr char kStatus[] = "/proc/thread-self/status";
constexpr int kRounds = 4;

struct Observation {
    int open_error = 0;
    ssize_t write_ret = -1;
    int write_error = 0;
    ssize_t read_ret = -1;
    int read_error = 0;
    std::string response;
};

std::string read_text(const char* path) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    char buf[8192];
    const ssize_t count = read(fd, buf, sizeof(buf));
    close(fd);
    if (count <= 0 || count == static_cast<ssize_t>(sizeof(buf))) return {};
    std::string result(buf, static_cast<size_t>(count));
    while (!result.empty() && (result.back() == '\n' || result.back() == '\0'))
        result.pop_back();
    return result;
}

Observation query(const std::string& input, const char* path = kAccess) {
    Observation r;
    const int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        r.open_error = errno;
        return r;
    }
    errno = 0;
    r.write_ret = write(fd, input.data(), input.size());
    r.write_error = r.write_ret < 0 ? errno : 0;
    if (r.write_ret == static_cast<ssize_t>(input.size())) {
        char response[512];
        errno = 0;
        r.read_ret = read(fd, response, sizeof(response));
        r.read_error = r.read_ret < 0 ? errno : 0;
        if (r.read_ret > 0 && r.read_ret < static_cast<ssize_t>(sizeof(response))) {
            r.response.assign(response, static_cast<size_t>(r.read_ret));
            while (!r.response.empty() &&
                   (r.response.back() == '\0' || r.response.back() == '\n'))
                r.response.pop_back();
        }
    }
    close(fd);
    return r;
}

void emit(std::ostringstream& out, const char* name, int round,
          const std::string& payload, const Observation& r,
          const char* field = "access_tail_case") {
    out << field << "=" << name << " round=" << round
        << " size=" << payload.size()
        << " open_errno=" << r.open_error
        << " write_ret=" << r.write_ret
        << " write_errno=" << r.write_error
        << " read_ret=" << r.read_ret
        << " read_errno=" << r.read_error
        << " response=[" << r.response << "]\n";
}

std::string run() {
    std::ostringstream out;
    out << "== xxksu SELinuxFS ignored access tail ==\n";
    const auto carrier = read_text(kCurrent);
    const auto enforcing = read_text(kEnforce);
    const auto status = read_text(kStatus);
    const auto index = read_text(kClass);
    const std::string prefix = "u:r:app_zygote:s0";
    const size_t seccomp = status.find("Seccomp:");
    int seccomp_value = -1;
    if (seccomp != std::string::npos) {
        const char* begin = status.c_str() + seccomp + strlen("Seccomp:");
        seccomp_value = static_cast<int>(strtol(begin, nullptr, 10));
    }
    out << "access_tail_pid=" << getpid() << " uid=" << getuid()
        << " carrier=" << carrier << " enforcing=" << enforcing
        << " seccomp=" << seccomp_value << '\n';
    if (getuid() < 10000 ||
        (carrier != prefix &&
         (carrier.rfind(prefix + ":c", 0) != 0)) ||
        enforcing != "1" || seccomp_value != 2) {
        out << "access_tail_status=unavailable reason=carrier_enforcing_seccomp\n";
        return out.str();
    }
    if (index.empty() || index.find_first_not_of("0123456789") != std::string::npos) {
        out << "access_tail_status=unavailable reason=process_class\n";
        return out.str();
    }
    const long tclass = strtol(index.c_str(), nullptr, 10);
    if (tclass <= 0 || tclass > 65535) {
        out << "access_tail_status=unavailable reason=process_class\n";
        return out.str();
    }
    const std::string base = carrier + " " + carrier + " " + index;
    out << "access_tail_prefix=" << base << '\n';
    const std::vector<std::pair<const char*, std::string>> cases = {
        {"base", base},
        {"tail_inv", base + " :inv:"},
        {"tail_ksu", base + " :ksu:"},
        {"tail_inv_file", base + " :inv_file:"},
        {"tail_ksu_file", base + " :ksu_file:"},
        {"tail_ksu_partial", base + " :ksuX"},
        {"invalid_source", "u:r:__access_tail_absent__:s0 " + carrier + " " + index},
    };
    for (int round = 0; round < kRounds; ++round) {
        for (size_t i = 0; i < cases.size(); ++i) {
            const auto& c = cases[(round & 1) ? cases.size() - 1 - i : i];
            emit(out, c.first, round, c.second, query(c.second));
        }
    }
    // /context parses a C-string ending at the first NUL. The hooked
    // SELinux Hide scanner can still inspect the full transaction length.
    // Preserve this as an independent sub-experiment of the same scanner,
    // not a second statistically independent root indicator.
    constexpr char kContext[] = "/sys/fs/selinux/context";
    const std::vector<std::pair<const char*, std::string>> context_cases = {
        {"context_base", carrier},
        {"context_nul_inv", carrier + std::string("\0 :inv:", 7)},
        {"context_nul_ksu", carrier + std::string("\0 :ksu:", 7)},
        {"context_nul_inv_file", carrier + std::string("\0 :inv_file:", 12)},
        {"context_nul_ksu_file", carrier + std::string("\0 :ksu_file:", 12)},
        {"context_nul_ksu_partial", carrier + std::string("\0 :ksuX", 7)},
    };
    out << "context_nul_prefix=" << carrier << '\n';
    for (int round = 0; round < kRounds; ++round) {
        for (size_t j = 0; j < context_cases.size(); ++j) {
            const auto& entry = context_cases[(round & 1) ?
                context_cases.size() - j - 1 : j];
            emit(out, entry.first, round, entry.second,
                 query(entry.second, kContext), "context_nul_case");
        }
    }
    out << "context_nul_status=complete\n";
    const std::string after = read_text(kCurrent);
    out << "access_tail_status=complete identity_unchanged="
        << (after == carrier ? "true" : "false") << '\n';
    return out.str();
}
}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxRawAccess_nativeProbeXxksuAccessTail(
        JNIEnv* env, jobject) {
    const auto result = run();
    return env->NewStringUTF(result.c_str());
}
