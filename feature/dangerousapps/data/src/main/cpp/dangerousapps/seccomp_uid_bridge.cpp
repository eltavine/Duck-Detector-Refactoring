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

#include <jni.h>
#include "seccomp_uid_protocol.h"
#include "common/disposable_child.h"
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace duckdetector::dangerousapps::seccomp_uid {
namespace {
bool write_result(int fd, const Result &result) {
    const auto *data = reinterpret_cast<const unsigned char *>(&result);
    size_t written = 0;
    while (written < sizeof(result)) {
        const ssize_t count = write(fd, data + written, sizeof(result) - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<size_t>(count);
    }
    return true;
}

void read_kernel_version(Result &result) {
    utsname release{};
    if (syscall(SYS_uname, &release) != 0) return;
    const char *cursor = release.release;
    int major = 0;
    int minor = 0;
    while (*cursor >= '0' && *cursor <= '9') {
        if (major > 100000) break;
        major = major * 10 + (*cursor - '0');
        ++cursor;
    }
    if (*cursor == '.') {
        ++cursor;
        while (*cursor >= '0' && *cursor <= '9') {
            if (minor > 100000) break;
            minor = minor * 10 + (*cursor - '0');
            ++cursor;
        }
    }
    if (major > 0) {
        result.kernel_major = major;
        result.kernel_minor = minor;
    }
}

int classify_install_error(int error) {
    switch (error) {
        case EBUSY: return kForeignListener;
        case EINVAL:
        case ENOSYS: return kUnsupported;
        case EPERM:
        case EACCES: return kRestricted;
        default: return kFailure;
    }
}

// Returns the listener fd or -1 with errno copied to error. The filter matches only
// getpriority(PRIO_USER, *), whose notification arrives before the syscall runs.
int install_listener(int *error) {
    // All supported Android ABIs are little-endian, so the 32-bit load at args[0] is the low
    // word of the int that carries PRIO_USER. The query child has the same ABI as this filter.
    sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArch, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpriority, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, args)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PRIO_USER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    sock_fprog program{};
    program.len = static_cast<unsigned short>(sizeof(code) / sizeof(code[0]));
    program.filter = code;
    errno = 0;
    const long fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                            SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    if (fd < 0) {
        *error = errno;
        return -1;
    }
    *error = 0;
    return static_cast<int>(fd);
}

// All buffers and listener ownership remain inside the disposable coordinator.
int collect(int fd, int first_uid, int last_uid) {
    Result result{};
    result.version = kVersion;
    result.first_suppressed = result.last_suppressed = -1;
    result.query_outcome = kQueryNotRun;
    read_kernel_version(result);
    seccomp_notif_sizes sizes{};
    if (kAuditArch == 0 || syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        result.install_error = kAuditArch == 0 ? ENOTSUP : errno;
        result.install_status = classify_install_error(result.install_error);
        // Only an actual NEW_LISTENER attempt may produce listener-collision evidence.
        if (result.install_status == kForeignListener) result.install_status = kFailure;
        if (kAuditArch == 0) result.install_status = kUnsupported;
    } else if (sizes.seccomp_notif != sizeof(seccomp_notif) ||
               sizes.seccomp_notif_resp != sizeof(seccomp_notif_resp) ||
               sizes.seccomp_data != sizeof(seccomp_data)) {
        result.install_status = kUnsupported;
        result.install_error = EPROTONOSUPPORT;
    } else if (syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 &&
               syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        result.install_error = errno;
        result.install_status = (errno == EPERM || errno == EACCES) ? kRestricted : kFailure;
    } else {
        int error = 0;
        const int listener = install_listener(&error);
        if (listener < 0) {
            result.install_status = classify_install_error(error);
            result.install_error = error;
        } else {
            result.install_status = kInstalled;
            service_queries(listener, fd, first_uid, last_uid, result);
            close(listener);
        }
    }
    return write_result(fd, result) ? 0 : 1;
}
} // namespace

bool valid_result(const Result &r, int first_uid, int last_uid) {
    const int span = last_uid - first_uid + 1;
    if (r.version != kVersion || r.install_status < kInstalled || r.install_status > kInstallTrapped ||
        r.kernel_major < 0 || r.kernel_minor < 0 || r.queried < 0 || r.queried > span ||
        r.notified < 0 || r.notified > span || r.query_outcome < kQueryComplete ||
        r.query_outcome > kQueryNotRun || (r.self_notified != 0 && r.self_notified != 1)) return false;
    if (r.install_status == kForeignListener && r.install_error != EBUSY) return false;
    if (r.install_status == kInstallTrapped && r.install_error != SIGSYS) return false;
    if (r.query_outcome == kQueryTrapped && r.query_error != SIGSYS) return false;
    if (r.install_status != kInstalled) {
        return r.queried == 0 && r.notified == 0 && r.first_suppressed == -1 &&
               r.last_suppressed == -1 && r.query_outcome == kQueryNotRun && r.self_notified == 0;
    }
    if (r.install_error != 0) return false;
    if (r.query_outcome != kQueryComplete) {
        return r.query_outcome != kQueryNotRun && r.queried == 0 &&
               r.first_suppressed == -1 && r.last_suppressed == -1;
    }
    if (r.query_error != 0 || r.queried != span || r.notified > r.queried) return false;
    if (r.notified == r.queried) {
        return r.first_suppressed == -1 && r.last_suppressed == -1 && r.self_notified == 1;
    }
    const int missing = r.queried - r.notified;
    if (r.first_suppressed < first_uid || r.last_suppressed > last_uid ||
        r.last_suppressed < r.first_suppressed ||
        missing > r.last_suppressed - r.first_suppressed + 1) return false;
    if (missing == 1 && r.first_suppressed != r.last_suppressed) return false;
    if (r.notified == 0 && (r.first_suppressed != first_uid || r.last_suppressed != last_uid)) return false;
    return true;
}

Result run_probe(int first_uid, int last_uid) {
    Result result{};
    result.version = kVersion;
    result.first_suppressed = result.last_suppressed = -1;
    result.query_outcome = kQueryNotRun;
    if (first_uid < 0 || last_uid < first_uid ||
        static_cast<int64_t>(last_uid) - first_uid >= kMaxSpan) {
        result.install_status = kFailure;
        result.install_error = EINVAL;
        return result;
    }
    std::array<unsigned char, sizeof(Result)> buffer{};
    const auto outcome = duckdetector::common::run_disposable_child(buffer,
        duckdetector::common::ChildDeadlines{std::chrono::milliseconds{2500}, std::chrono::milliseconds{250}},
        [first_uid, last_uid](int fd) { return collect(fd, first_uid, last_uid); });
    using duckdetector::common::ChildEnd;
    if (outcome.end == ChildEnd::kExited && outcome.exit_status == 0 && outcome.report_length == sizeof(Result)) {
        std::memcpy(&result, buffer.data(), sizeof(result));
        if (valid_result(result, first_uid, last_uid)) return result;
        result = Result{};
        result.version = kVersion;
        result.first_suppressed = result.last_suppressed = -1;
        result.query_outcome = kQueryNotRun;
        result.install_error = EPROTO;
    } else {
        result.install_error = outcome.signal != 0 ? outcome.signal : outcome.error;
        if (outcome.end == ChildEnd::kTimedOut || outcome.end == ChildEnd::kNotReaped)
            result.install_error = ETIMEDOUT;
        if (outcome.end == ChildEnd::kSeccompTrapped) result.install_error = SIGSYS;
    }
    result.install_status = outcome.end == ChildEnd::kSeccompTrapped ? kInstallTrapped : kFailure;
    if (result.install_error == 0) result.install_error = EIO;
    return result;
}
} // namespace duckdetector::dangerousapps::seccomp_uid

extern "C" JNIEXPORT jintArray JNICALL
Java_com_eltavine_duckdetector_features_dangerousapps_data_probes_hma_HmaSeccompUidBridge_nativeProbe(
        JNIEnv *env, jobject, jint first_uid, jint last_uid) {
    const auto result = duckdetector::dangerousapps::seccomp_uid::run_probe(first_uid, last_uid);
    const std::array<jint, 12> values{
        result.version, result.install_status, result.install_error,
        result.kernel_major, result.kernel_minor, result.queried, result.notified,
        result.first_suppressed, result.last_suppressed, result.query_outcome,
        result.query_error, result.self_notified,
    };
    const jintArray output = env->NewIntArray(static_cast<jsize>(values.size()));
    if (output != nullptr) env->SetIntArrayRegion(output, 0, static_cast<jsize>(values.size()), values.data());
    return output;
}
