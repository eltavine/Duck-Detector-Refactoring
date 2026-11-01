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

#include "initrc_timing_probe.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <future>
#include <new>
#include <string>
#include <system_error>
#include <time.h>
#include <unistd.h>

#if defined(__ANDROID__) && defined(__aarch64__)
#include <sched.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

namespace duckdetector::nativeroot {
namespace {
constexpr std::int64_t kBudgetNanos = 1'000'000'000;
constexpr int kOrders[4][4] = {{0, 1, 3, 2}, {1, 2, 0, 3}, {2, 3, 1, 0}, {3, 0, 2, 1}};

#if defined(__ANDROID__) && defined(__aarch64__)
int set_name(const char *name) { return prctl(PR_SET_NAME, name, 0UL, 0UL, 0UL); }
int get_name(char *name) { return prctl(PR_GET_NAME, name, 0UL, 0UL, 0UL); }
int pin_cpu() {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &allowed)) continue;
        cpu_set_t one;
        CPU_ZERO(&one);
        CPU_SET(cpu, &one);
        return sched_setaffinity(0, sizeof(one), &one) == 0 ? cpu : -1;
    }
    errno = EINVAL;
    return -1;
}
int verify_affinity(int expected_cpu) {
    cpu_set_t current;
    CPU_ZERO(&current);
    if (sched_getaffinity(0, sizeof(current), &current) != 0) return -1;
    if (CPU_COUNT(&current) != 1 || !CPU_ISSET(expected_cpu, &current)) {
        errno = EAGAIN;
        return -1;
    }
    return 0;
}
int stat_fd(int fd, struct stat *value) {
    // Bionic Android 16 SYSCALLS.TXT maps lp64 fstat to this native syscall/structure.
    // fstatat is a different syscall and would not exercise the reviewed KSU hook.
    return static_cast<int>(syscall(__NR_fstat, fd, value));
}
std::int64_t monotonic_now() {
    timespec value{};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return static_cast<std::int64_t>(value.tv_sec) * 1'000'000'000 + value.tv_nsec;
}
const InitRcTimingIo kIo{set_name, get_name, pin_cpu, sched_getcpu, stat_fd, monotonic_now, verify_affinity};
#endif

void fail(InitRcTimingResult &result, InitRcTimingStage stage, int error) {
    if (result.stage == InitRcTimingStage::COLLECTED) {
        result.stage = stage;
        result.error = error;
    }
}
// Re-observing one descriptor: every field, including the inode, must stay stable.
bool same_file(const struct stat &a, const struct stat &b) {
    return S_ISREG(a.st_mode) && S_ISREG(b.st_mode) && a.st_dev == b.st_dev &&
           a.st_ino == b.st_ino && a.st_mode == b.st_mode && a.st_size == b.st_size &&
           a.st_nlink == 1 && b.st_nlink == 1 && a.st_uid == b.st_uid && a.st_gid == b.st_gid;
}

// Android's SELinux policy never allows an untrusted app to create a hard link, so the
// control is a second independent file with identical metadata. The reviewed hook compares
// comm, file type, dentry name and d_path only; it never reads st_ino.
bool same_metadata(const struct stat &control, const struct stat &target) {
    return S_ISREG(control.st_mode) && S_ISREG(target.st_mode) &&
           control.st_dev == target.st_dev && control.st_ino != target.st_ino &&
           control.st_mode == target.st_mode && control.st_size == target.st_size &&
           control.st_nlink == 1 && target.st_nlink == 1 &&
           control.st_uid == target.st_uid && control.st_gid == target.st_gid;
}
struct Worker {
    const InitRcTimingIo &io;
    int control_fd;
    int target_fd;
    struct stat expected_control;
    struct stat expected_target;
    InitRcTimingResult &result;
};

bool check_cpu(Worker &worker) {
    if (worker.io.verify_affinity(worker.result.cpu) != 0) {
        fail(worker.result, InitRcTimingStage::AFFINITY_FAILED, errno);
        return false;
    }
    const int cpu = worker.io.current_cpu();
    if (cpu == worker.result.cpu) return true;
    fail(worker.result, InitRcTimingStage::AFFINITY_FAILED, cpu < 0 ? errno : EAGAIN);
    return false;
}

bool check_name(Worker &worker, const char *name) {
    char actual[16]{};
    if (worker.io.get_name(actual) != 0) {
        fail(worker.result, InitRcTimingStage::NAME_FAILED, errno);
        return false;
    }
    if (std::strncmp(name, actual, sizeof(actual)) != 0) {
        fail(worker.result, InitRcTimingStage::NAME_FAILED, EIO);
        return false;
    }
    return true;
}

bool batch(Worker &worker, int condition, std::int64_t &duration) {
    auto &out = worker.result;
    const auto &io = worker.io;
    const char *name = condition >= 2 ? "init" : "duck";
    if (io.set_name(name) != 0) {
        fail(out, InitRcTimingStage::NAME_FAILED, errno);
        return false;
    }
    if (!check_name(worker, name) || !check_cpu(worker)) return false;
    const bool target = condition % 2 != 0;
    const int fd = target ? worker.target_fd : worker.control_fd;
    const struct stat &expected = target ? worker.expected_target : worker.expected_control;
    struct stat attributes{};
    const std::int64_t begin = io.now();
    if (begin <= 0) {
        fail(out, InitRcTimingStage::CLOCK_FAILED, errno);
        return false;
    }
    // No allocation, JNI, name/affinity change or formatting inside the timed batch.
    for (int i = 0; i < kInitRcIterations; ++i) {
        if (io.stat_fd(fd, &attributes) != 0) {
            fail(out, InitRcTimingStage::SYSCALL_FAILED, errno);
            return false;
        }
        // Validate each result: a transient mismatch can disappear before the batch's final call.
        if (!same_file(expected, attributes)) {
            fail(out, InitRcTimingStage::SYSCALL_FAILED, ESTALE);
            return false;
        }
    }
    const std::int64_t end = io.now();
    if (end <= begin) {
        fail(out, InitRcTimingStage::CLOCK_FAILED, end <= 0 ? errno : EIO);
        return false;
    }
    if (!check_name(worker, name) || !check_cpu(worker)) return false;
    duration = end - begin;
    return true;
}

void *measure(void *argument) {
    auto &worker = *static_cast<Worker *>(argument);
    auto &out = worker.result;
    const auto &io = worker.io;
    char original[16]{};
    if (io.get_name(original) != 0) {
        fail(out, InitRcTimingStage::NAME_FAILED, errno);
        return nullptr;
    }
    out.cpu = io.pin_cpu();
    if (out.cpu < 0) {
        fail(out, InitRcTimingStage::AFFINITY_FAILED, errno);
        return nullptr;
    }
    const std::int64_t start = io.now();
    if (start <= 0) fail(out, InitRcTimingStage::CLOCK_FAILED, errno);
    // One balanced warm-up round, then exactly eight cycles of four balanced orders.
    for (int round = -1; round < static_cast<int>(kInitRcRounds) &&
                         out.stage == InitRcTimingStage::COLLECTED; ++round) {
        InitRcRound values{};
        for (int slot = 0; slot < 4; ++slot) {
            const auto now = io.now();
            if (now < start || now <= 0) {
                fail(out, InitRcTimingStage::CLOCK_FAILED, EIO);
                break;
            }
            if (now - start >= kBudgetNanos) {
                fail(out, InitRcTimingStage::TIMED_OUT, ETIMEDOUT);
                break;
            }
            const int condition = kOrders[round < 0 ? 0 : round % 4][slot];
            if (!batch(worker, condition, values[condition])) break;
            const auto after = io.now();
            if (after <= 0 || after < now) {
                fail(out, InitRcTimingStage::CLOCK_FAILED, EIO);
                break;
            }
            if (after - start >= kBudgetNanos) {
                fail(out, InitRcTimingStage::TIMED_OUT, ETIMEDOUT);
                break;
            }
        }
        if (round >= 0 && out.stage == InitRcTimingStage::COLLECTED)
            out.rounds[out.count++] = values;
    }
    // Only this worker's comm/affinity were changed; it exits immediately after restoration.
    if (io.set_name(original) != 0) {
        fail(out, InitRcTimingStage::NAME_FAILED, errno);
    }
    return nullptr;
}

InitRcTimingResult run(const char *base, const InitRcTimingIo &io) {
    InitRcTimingResult out;
    if (!base || base[0] != '/') {
        fail(out, InitRcTimingStage::FILE_FAILED, EINVAL);
        return out;
    }
    char *canonical = realpath(base, nullptr);
    if (!canonical) {
        fail(out, InitRcTimingStage::FILE_FAILED, errno);
        return out;
    }
    std::string directory = std::string(canonical) + "/initrc-XXXXXX";
    free(canonical);
    // A longer path cannot exercise the reviewed hook's successful 256-byte d_path branch.
    if (directory.size() + std::strlen("/init.rc") >= 256 || !mkdtemp(directory.data())) {
        fail(out, InitRcTimingStage::FILE_FAILED,
             directory.size() + std::strlen("/init.rc") >= 256 ? ENAMETOOLONG : errno);
        return out;
    }
    const std::string control = directory + "/data.rc", target = directory + "/init.rc";
    // Android never allows an untrusted app to create a hard link, so the control is a
    // second independent file rather than another name for the same inode.
    int control_fd = open(control.c_str(), O_CREAT | O_EXCL | O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    int target_fd = -1;
    bool target_created = false;
    if (control_fd < 0) {
        fail(out, InitRcTimingStage::FILE_FAILED, errno);
    } else {
        target_fd = open(target.c_str(), O_CREAT | O_EXCL | O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (target_fd < 0) fail(out, InitRcTimingStage::FILE_FAILED, errno);
        else target_created = true;
    }
    struct stat expected_control{}, expected_target{};
    if (out.stage == InitRcTimingStage::COLLECTED) {
        if (fstat(control_fd, &expected_control) != 0 || fstat(target_fd, &expected_target) != 0)
            fail(out, InitRcTimingStage::FILE_FAILED, errno);
        else if (!same_metadata(expected_control, expected_target))
            fail(out, InitRcTimingStage::FILE_FAILED, ESTALE);
    }
    if (out.stage == InitRcTimingStage::COLLECTED) {
        Worker worker{io, control_fd, target_fd, expected_control, expected_target, out};
        try {
            // Explicit async forbids deferred execution on the caller. The standard's
            // futures.async completion guarantee also protects worker/FD lifetimes on exceptions.
            auto completion = std::async(std::launch::async, [&worker] { measure(&worker); });
            completion.get();
        } catch (const std::system_error &error) {
            fail(out, InitRcTimingStage::THREAD_FAILED, error.code().value());
        } catch (const std::bad_alloc &) {
            fail(out, InitRcTimingStage::THREAD_FAILED, ENOMEM);
        } catch (...) {
            fail(out, InitRcTimingStage::THREAD_FAILED, EIO);
        }
    }
    // close(EINTR) must not be retried: Android may have already released/reused the descriptor.
    auto cleanup = [&](int status) {
        if (status != 0 && !out.cleanup_error) out.cleanup_error = errno;
    };
    if (target_fd >= 0) cleanup(close(target_fd));
    if (control_fd >= 0) cleanup(close(control_fd));
    if (target_created) cleanup(unlink(target.c_str()));
    if (control_fd >= 0) cleanup(unlink(control.c_str()));
    cleanup(rmdir(directory.c_str()));
    out.cleanup_complete = out.cleanup_error == 0;
    if (!out.cleanup_complete) fail(out, InitRcTimingStage::CLEANUP_FAILED, out.cleanup_error);
    return out;
}
}  // namespace

InitRcTimingResult collect_initrc_timing(const char *directory, const InitRcTimingIo *injected) {
    if (injected) return run(directory, *injected);
#if defined(__ANDROID__) && defined(__aarch64__)
    return run(directory, kIo);
#else
    InitRcTimingResult result;
    result.stage = InitRcTimingStage::UNSUPPORTED_ABI;
    return result;
#endif
}
}  // namespace duckdetector::nativeroot
