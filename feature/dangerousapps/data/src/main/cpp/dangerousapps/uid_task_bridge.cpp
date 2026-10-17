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
#include "common/disposable_child.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace {
constexpr int kMaxHits = 512;
constexpr int kComplete = 0;
constexpr int kPartial = 1;
constexpr int kRestricted = 2;
constexpr int kSignaled = 3;
constexpr int kTimeout = 4;
constexpr int kFailure = 5;
struct Hit { int uid; int raw_priority; };
struct Scan {
    int status = kFailure;
    int checked = 0;
    int error = 0;
    int self_priority = 0;
    int count = 0;
    std::array<Hit, kMaxHits> hits{};
};

int64_t monotonic_ns() {
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return static_cast<int64_t>(value.tv_sec) * 1000000000LL + value.tv_nsec;
}

bool write_scan(int fd, const Scan &scan) {
    const auto *data = reinterpret_cast<const unsigned char *>(&scan);
    size_t written = 0;
    while (written < sizeof(scan)) {
        const ssize_t count = write(fd, data + written, sizeof(scan) - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        written += static_cast<size_t>(count);
    }
    return true;
}

// This body runs after fork: fixed-size stack data and async-signal-safe platform calls only.
int collect(int fd, int first_uid, int last_uid) {
    Scan scan{};
    errno = 0;
    scan.self_priority = static_cast<int>(syscall(SYS_getpriority, PRIO_USER, getuid()));
    if (scan.self_priority < 1 || scan.self_priority > 40) {
        scan.error = errno != 0 ? errno : EPROTO;
        scan.status = (scan.error == EPERM || scan.error == EACCES) ? kRestricted : kFailure;
        return write_scan(fd, scan) ? 0 : 1;
    }
    const int64_t start = monotonic_ns();
    if (start < 0) { scan.error = errno; return write_scan(fd, scan) ? 0 : 1; }
    scan.status = kComplete;
    for (int64_t candidate = first_uid; candidate <= last_uid; ++candidate) {
        const int uid = static_cast<int>(candidate);
        if ((scan.checked % 16) == 0) {
            const int64_t now = monotonic_ns();
            if (now < 0) { scan.status = kFailure; scan.error = errno; break; }
            if (now - start >= 500000000LL) { scan.status = kPartial; break; }
        }
        errno = 0;
        const long value = syscall(SYS_getpriority, PRIO_USER, uid);
        ++scan.checked;
        if (value == -1 && errno == ESRCH) continue;
        if (value < 1 || value > 40) {
            scan.error = errno != 0 ? errno : EPROTO;
            scan.status = (scan.error == EPERM || scan.error == EACCES) ? kRestricted : kFailure;
            break;
        }
        if (scan.count == kMaxHits) { scan.status = kPartial; break; }
        scan.hits[scan.count++] = Hit{uid, static_cast<int>(value)};
    }
    return write_scan(fd, scan) ? 0 : 1;
}

bool valid_scan(const Scan &scan, int first_uid, int last_uid) {
    if (scan.status < kComplete || scan.status > kFailure || scan.checked < 0 ||
        scan.checked > last_uid - first_uid + 1 || scan.count < 0 ||
        scan.count > kMaxHits || scan.count > scan.checked) return false;
    if (scan.status == kComplete && scan.checked != last_uid - first_uid + 1) return false;
    if ((scan.status == kComplete || scan.status == kPartial) &&
        (scan.self_priority < 1 || scan.self_priority > 40 || scan.error != 0)) return false;
    int previous = first_uid - 1;
    for (int index = 0; index < scan.count; ++index) {
        const auto &hit = scan.hits[index];
        if (hit.uid <= previous || static_cast<int64_t>(hit.uid) >=
            static_cast<int64_t>(first_uid) + scan.checked ||
            hit.raw_priority < 1 || hit.raw_priority > 40) return false;
        previous = hit.uid;
    }
    return true;
}
} // namespace

extern "C" JNIEXPORT jintArray JNICALL
Java_com_eltavine_duckdetector_features_dangerousapps_data_probes_hma_HmaUidTaskBridge_nativeScan(
        JNIEnv *env, jobject, jint first_uid, jint last_uid) {
    Scan scan{};
    if (first_uid < 0 || last_uid < first_uid || last_uid - first_uid > 9999) {
        scan.error = EINVAL;
    } else {
        std::array<unsigned char, sizeof(Scan)> buffer{};
        const auto outcome = duckdetector::common::run_disposable_child(
            buffer, duckdetector::common::ChildDeadlines{},
            [first_uid, last_uid](int fd) { return collect(fd, first_uid, last_uid); });
        using duckdetector::common::ChildEnd;
        if (outcome.end == ChildEnd::kExited && outcome.exit_status == 0 &&
            outcome.report_length == sizeof(Scan)) {
            std::memcpy(&scan, buffer.data(), sizeof(scan));
            // Validate before indexing child-provided counts, not only in the Kotlin parser.
            if (!valid_scan(scan, first_uid, last_uid)) {
                scan = Scan{};
                scan.error = EPROTO;
            }
        } else {
            switch (outcome.end) {
                case ChildEnd::kSeccompTrapped: scan.status = kRestricted; break;
                case ChildEnd::kSignaled: scan.status = kSignaled; break;
                case ChildEnd::kTimedOut:
                case ChildEnd::kNotReaped: scan.status = kTimeout; break;
                default: scan.status = kFailure; break;
            }
            scan.error = outcome.signal != 0 ? outcome.signal : outcome.error;
        }
    }
    // Versioned integer payload: no locale, errno text or ABI-dependent struct crosses JNI.
    std::vector<jint> values{1, scan.status, scan.checked, scan.error, scan.self_priority, scan.count};
    for (int index = 0; index < scan.count; ++index) {
        values.push_back(scan.hits[index].uid);
        values.push_back(scan.hits[index].raw_priority);
    }
    const jintArray result = env->NewIntArray(static_cast<jsize>(values.size()));
    if (result != nullptr) env->SetIntArrayRegion(result, 0, static_cast<jsize>(values.size()), values.data());
    return result;
}
