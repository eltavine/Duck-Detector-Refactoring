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

// SELinuxFS same-file-descriptor transaction-state experiment, observed with
// xxksu (backslashxx fork) SELinux Hide OFF/ON on an Android 14 ARM64 app_zygote.
// Runs exclusively in the app_zygote preload parent, without root.
// Unlike a timing test, it observes the second write's errno on the SAME fd.
// /sys/fs/selinux/context validates labels; it does not change process identity.
#include <jni.h>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>

namespace {

constexpr char kContextNode[] = "/sys/fs/selinux/context";
constexpr char kCurrentAttr[] = "/proc/thread-self/attr/current";
constexpr char kEnforceNode[] = "/sys/fs/selinux/enforce";
constexpr char kInvalid[] = "u:r:__fd_reuse_probe_absent__:s0";
// These are the actual SELinux policy labels used by xxksu. Do not rename
// their byte sequences when adjusting the detector's user-facing branding.
constexpr char kXxksuDomain[] = "u:r:ksu:s0";
constexpr char kXxksuFile[] = "u:object_r:ksu_file:s0";

struct WriteResult {
    ssize_t bytes = -1;
    int error = 0;
};

struct Sequence {
    int open_error = 0;
    WriteResult first;
    WriteResult second;
};

std::string read_text(const char* path, int& error) {
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        error = errno;
        return {};
    }
    char buffer[512];
    ssize_t count;
    do {
        count = read(fd, buffer, sizeof(buffer));
    } while (count < 0 && errno == EINTR);
    error = count < 0 ? errno : 0;
    close(fd);
    if (count <= 0 || count == static_cast<ssize_t>(sizeof(buffer))) return {};
    std::string value(buffer, static_cast<size_t>(count));
    while (!value.empty() && (value.back() == '\n' || value.back() == '\0'))
        value.pop_back();
    return value;
}

WriteResult write_context(const int fd, const std::string& context) {
    WriteResult result;
    errno = 0;
    result.bytes = write(fd, context.data(), context.size());
    result.error = result.bytes < 0 ? errno : 0;
    return result;
}

Sequence two_writes(const std::string& first, const std::string& second) {
    Sequence result;
    const int fd = open(kContextNode, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        result.open_error = errno;
        return result;
    }
    result.first = write_context(fd, first);
    // Deliberately do not close, seek, or reopen: preserve file->private_data.
    result.second = write_context(fd, second);
    close(fd);
    return result;
}

bool matches(const WriteResult& r, const int expected_error, const ssize_t expected_bytes = -1) {
    return r.bytes == expected_bytes && r.error == expected_error;
}

bool succeeded(const WriteResult& r, const std::string& context) {
    return r.error == 0 && r.bytes == static_cast<ssize_t>(context.size());
}

bool is_ebusy(const WriteResult& r) { return matches(r, EBUSY); }
bool is_einval(const WriteResult& r) { return matches(r, EINVAL); }

void print_write(std::ostringstream& out, const WriteResult& r) {
    out << "ret=" << r.bytes << " errno=" << r.error;
}

void print_sequence(std::ostringstream& out, const char* label, const Sequence& s) {
    out << "fd_reuse_case=" << label << " open_errno=" << s.open_error << " first_";
    print_write(out, s.first);
    out << " second_";
    print_write(out, s.second);
    out << '\n';
}

// Only a complete pair of mutually corroborating observations is a candidate.
// No positive/negative state is a universal xxksu or root verdict.
const char* classify_candidate(const Sequence& valid, const Sequence& invalid,
                                const std::string& carrier, const std::string& candidate) {
    if (valid.open_error || invalid.open_error) return "INCONCLUSIVE_open";
    if (is_einval(valid.first) && is_einval(invalid.first)) {
        if (succeeded(valid.second, carrier) && is_einval(invalid.second))
            return "EARLY_RETURN_CANDIDATE";
        if (is_ebusy(valid.second) && is_ebusy(invalid.second))
            return "NO_BYPASS_OBSERVED";
    }
    if (succeeded(valid.first, candidate) && succeeded(invalid.first, candidate) &&
        is_ebusy(valid.second) && is_ebusy(invalid.second))
        return "NO_BYPASS_OBSERVED_VALID_CANDIDATE";
    return "INCONCLUSIVE_mixed_outcomes";
}

std::string run_fd_reuse_probe() {
    std::ostringstream out;
    out << "== xxksu SELinuxFS same-FD transaction state ==\n";
    out << "fd_reuse_pid=" << getpid() << " fd_reuse_uid=" << getuid() << '\n';

    int error = 0;
    const std::string carrier = read_text(kCurrentAttr, error);
    out << "fd_reuse_carrier=" << (carrier.empty() ? "unavailable" : carrier)
        << " read_errno=" << error << '\n';
    if (getuid() < 10000 || carrier.rfind("u:r:app_zygote:s0", 0) != 0) {
        out << "fd_reuse_verdict=UNAVAILABLE reason=requires_app_zygote_parent\n";
        return out.str();
    }
    const std::string enforcing = read_text(kEnforceNode, error);
    if (error != 0 || enforcing != "1") {
        out << "fd_reuse_verdict=UNAVAILABLE reason=selinux_enforcing_unverified errno="
            << error << '\n';
        return out.str();
    }

    // Run individual, independent-FD preflights before the state experiment.
    const Sequence valid_pre = two_writes(carrier, carrier);
    const Sequence invalid_pre = two_writes(kInvalid, kInvalid);
    print_sequence(out, "preflight_valid_valid", valid_pre);
    print_sequence(out, "preflight_invalid_invalid", invalid_pre);
    const bool preflight_ok = valid_pre.open_error == 0 &&
        succeeded(valid_pre.first, carrier) && is_ebusy(valid_pre.second) &&
        invalid_pre.open_error == 0 && is_einval(invalid_pre.first) &&
        is_ebusy(invalid_pre.second);
    out << "fd_reuse_preflight=" << (preflight_ok ? "PASS" : "FAIL") << '\n';
    if (!preflight_ok) {
        out << "fd_reuse_verdict=INCONCLUSIVE reason=stock_transaction_controls_failed\n";
        return out.str();
    }

    // The invalid control must consume the fd's only transaction even when
    // context parsing returns EINVAL, as in stock libfs/simple_transaction_get.
    const Sequence baseline = two_writes(kInvalid, carrier);
    print_sequence(out, "invalid_to_valid", baseline);
    if (baseline.open_error != 0 || !is_einval(baseline.first) ||
        !is_ebusy(baseline.second)) {
        out << "fd_reuse_verdict=INCONCLUSIVE reason=invalid_control_did_not_consume_fd\n";
        return out.str();
    }

    const Sequence domain_valid = two_writes(kXxksuDomain, carrier);
    const Sequence domain_invalid = two_writes(kXxksuDomain, kInvalid);
    const Sequence file_valid = two_writes(kXxksuFile, carrier);
    const Sequence file_invalid = two_writes(kXxksuFile, kInvalid);
    print_sequence(out, "xxksu_to_valid", domain_valid);
    print_sequence(out, "xxksu_to_invalid", domain_invalid);
    print_sequence(out, "xxksu_file_to_valid", file_valid);
    print_sequence(out, "xxksu_file_to_invalid", file_invalid);

    const char* domain_status = classify_candidate(domain_valid, domain_invalid, carrier, kXxksuDomain);
    // The xxksu file-type candidate may have a different byte length from the domain.
    const char* file_status = classify_candidate(file_valid, file_invalid, carrier, kXxksuFile);
    out << "fd_reuse_domain=" << domain_status << '\n'
        << "fd_reuse_file=" << file_status << '\n';
    if (!std::strcmp(domain_status, "EARLY_RETURN_CANDIDATE") ||
        !std::strcmp(file_status, "EARLY_RETURN_CANDIDATE")) {
        out << "fd_reuse_verdict=EARLY_RETURN_CANDIDATE "
               "reason=candidate_left_fd_unconsumed_not_root_attribution\n";
    } else if (!std::strncmp(domain_status, "NO_BYPASS", 9) &&
               !std::strncmp(file_status, "NO_BYPASS", 9)) {
        out << "fd_reuse_verdict=NO_BYPASS_OBSERVED "
               "reason=both_candidates_consumed_fd\n";
    } else {
        out << "fd_reuse_verdict=INCONCLUSIVE "
               "reason=mixed_or_unexpected_candidate_results\n";
    }
    return out.str();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxRawAccess_nativeProbeXxksuFdReuse(
        JNIEnv* env, jobject /* preload */) {
    const std::string report = run_fd_reuse_probe();
    return env->NewStringUTF(report.c_str());
}
