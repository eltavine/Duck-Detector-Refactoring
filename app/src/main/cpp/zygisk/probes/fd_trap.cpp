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

#include "zygisk/probes/fd_trap.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace duckdetector::zygisk {

    namespace {

        constexpr char kTrapSignature[] = "duckdetector:zygisk:fdtrap:v1";

        std::mutex g_details_mutex;
        std::string g_last_details = "FD trap has not run yet.";

        void set_details(const std::string &detail) {
            std::lock_guard<std::mutex> guard(g_details_mutex);
            g_last_details = detail;
        }

    }  // namespace

    int setup_trap_fd(const std::string &cache_dir) {
        int fd = -1;
#ifdef O_TMPFILE
        fd = open(cache_dir.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
#endif
        if (fd < 0) {
            std::string template_path = cache_dir + "/zygisk_fdtrap_XXXXXX";
            std::vector<char> scratch(template_path.begin(), template_path.end());
            scratch.push_back('\0');
            fd = mkstemp(scratch.data());
            if (fd < 0) {
                set_details("Trap setup failed: " + std::string(std::strerror(errno)));
                return kFdTrapNativeUnavailable;
            }
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            unlink(scratch.data());
        }

        const auto wrote = write(fd, kTrapSignature, sizeof(kTrapSignature) - 1);
        if (wrote != static_cast<ssize_t>(sizeof(kTrapSignature) - 1)) {
            set_details("Trap setup failed while writing the signature payload.");
            close(fd);
            return kFdTrapNativeUnavailable;
        }
        fsync(fd);
        lseek(fd, 0, SEEK_SET);
        set_details("Trap descriptor prepared with a deleted-path signature payload.");
        return fd;
    }

    int verify_trap_fd(const int fd) {
        struct stat status{};
        if (fstat(fd, &status) != 0) {
            if (errno == EBADF) {
                set_details(
                        "fstat returned EBADF. The trap descriptor was already closed in the specialized child process.");
                return kFdTrapEbadf;
            }
            set_details(
                    "fstat failed for the trap descriptor: " + std::string(std::strerror(errno)));
            return kFdTrapProcfsAnomaly;
        }

        std::array<char, sizeof(kTrapSignature)> buffer{};
        const auto read_bytes = pread(fd, buffer.data(), sizeof(kTrapSignature) - 1, 0);
        const std::string actual(buffer.data(),
                                 read_bytes > 0 ? static_cast<size_t>(read_bytes) : 0U);
        if (read_bytes != static_cast<ssize_t>(sizeof(kTrapSignature) - 1) ||
            actual != kTrapSignature) {
            set_details(
                    "Trap descriptor content drifted after specialization. Expected signature did not survive intact.");
            return kFdTrapCorruption;
        }

        char proc_path[64] = {};
        std::snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
        std::array<char, 512> target{};
        const auto link_length = readlink(proc_path, target.data(), target.size() - 1);
        if (link_length <= 0) {
            set_details(
                    "Trap descriptor remained readable, but /proc/self/fd no longer exposed a stable target for it.");
            return kFdTrapProcfsAnomaly;
        }

        target[static_cast<size_t>(link_length)] = '\0';
        set_details(
                "Trap descriptor survived specialization and still resolves through /proc/self/fd to " +
                std::string(target.data()) + ".");
        return kFdTrapClean;
    }

    std::string get_trap_details() {
        std::lock_guard<std::mutex> guard(g_details_mutex);
        return g_last_details;
    }

    void cleanup_trap_fd(const int fd) {
        if (fd >= 0) {
            close(fd);
        }
    }

}  // namespace duckdetector::zygisk
