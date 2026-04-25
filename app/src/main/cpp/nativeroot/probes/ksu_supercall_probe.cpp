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

#include "nativeroot/probes/ksu_supercall_probe.h"

#include <csignal>
#include <cstdint>
#include <string>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::nativeroot {
    namespace {

        constexpr unsigned int kKsuInstallMagic1 = 0xDEADBEEF;
        constexpr unsigned int kKsuInstallMagic2 = 0xCAFEBABE;

        constexpr unsigned int kKsuGetInfoFlagLkm = 1U << 0;
        constexpr unsigned int kKsuGetInfoFlagManager = 1U << 1;
        constexpr unsigned int kKsuGetInfoFlagLateLoad = 1U << 2;
        constexpr unsigned int kKsuGetInfoFlagPrBuild = 1U << 3;

        struct KsuGetInfoCmd {
            std::uint32_t version = 0;
            std::uint32_t flags = 0;
            std::uint32_t features = 0;
        };

        struct KsuCheckSafemodeCmd {
            std::uint8_t in_safe_mode = 0;
        };

        struct KsuSupercallPacket {
            std::uint32_t version = 0;
            std::uint32_t flags = 0;
            std::uint32_t features = 0;
            std::uint8_t in_safe_mode = 0;
            std::uint8_t safemode_supported = 0;
            std::uint8_t hit = 0;
        };

        constexpr unsigned long kKsuIoctlGetInfo = _IOC(_IOC_READ, 'K', 2, 0);
        constexpr unsigned long kKsuIoctlCheckSafemode = _IOC(_IOC_READ, 'K', 5, 0);

        bool collect_child_packet(
                KsuSupercallPacket &packet,
                bool &blocked_by_seccomp
        ) {
            int pipe_fds[2] = {-1, -1};
            if (pipe(pipe_fds) != 0) {
                return false;
            }

            fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC);
            fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC);

            const pid_t pid = fork();
            if (pid < 0) {
                close(pipe_fds[0]);
                close(pipe_fds[1]);
                return false;
            }

            if (pid == 0) {
                close(pipe_fds[0]);

                KsuSupercallPacket child_packet{};
#if defined(__NR_reboot)
                int driver_fd = -1;
                syscall(
                        __NR_reboot,
                        kKsuInstallMagic1,
                        kKsuInstallMagic2,
                        0,
                        &driver_fd
                );

                if (driver_fd >= 0) {
                    KsuGetInfoCmd info_cmd{};
                    if (ioctl(driver_fd, kKsuIoctlGetInfo, &info_cmd) == 0 &&
                        info_cmd.version != 0) {
                        child_packet.version = info_cmd.version;
                        child_packet.flags = info_cmd.flags;
                        child_packet.features = info_cmd.features;
                        child_packet.hit = 1;

                        KsuCheckSafemodeCmd safemode_cmd{};
                        if (ioctl(driver_fd, kKsuIoctlCheckSafemode, &safemode_cmd) == 0) {
                            child_packet.safemode_supported = 1;
                            child_packet.in_safe_mode = safemode_cmd.in_safe_mode;
                        }
                    }

                    close(driver_fd);
                }
#endif

                const ssize_t ignored = write(pipe_fds[1], &child_packet, sizeof(child_packet));
                (void) ignored;
                close(pipe_fds[1]);
                _exit(0);
            }

            close(pipe_fds[1]);

            int status = 0;
            if (waitpid(pid, &status, 0) < 0) {
                close(pipe_fds[0]);
                return false;
            }

            const ssize_t bytes_read = read(pipe_fds[0], &packet, sizeof(packet));
            close(pipe_fds[0]);

            if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
                blocked_by_seccomp = true;
                return false;
            }

            return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                   bytes_read == static_cast<ssize_t>(sizeof(packet));
        }

        Finding build_finding(
                const std::string &value,
                const std::string &detail,
                const Severity severity
        ) {
            return Finding{
                    .group = "SYSCALL",
                    .label = "KSU supercall",
                    .value = value,
                    .detail = detail,
                    .severity = severity,
            };
        }

    }  // namespace

    ProbeResult run_ksu_supercall_probe() {
        ProbeResult result;

        bool blocked_by_seccomp = false;
        KsuSupercallPacket packet{};
        if (!collect_child_packet(packet, blocked_by_seccomp)) {
            if (blocked_by_seccomp) {
                result.checked_count = 1;
                result.denied_count = 1;
            }
            return result;
        }

        result.checked_count = 1;
        if (packet.hit == 0 || packet.version == 0) {
            return result;
        }

        result.flags.kernel_su = true;
        result.hit_count = 1;
        result.numeric_value = static_cast<long>(packet.version);
        result.extra_numeric_value = static_cast<long>(packet.flags);

        const bool is_lkm = (packet.flags & kKsuGetInfoFlagLkm) != 0U;
        const bool is_late_load = (packet.flags & kKsuGetInfoFlagLateLoad) != 0U;
        const bool is_pr_build = (packet.flags & kKsuGetInfoFlagPrBuild) != 0U;
        const bool is_manager = (packet.flags & kKsuGetInfoFlagManager) != 0U;
        const bool in_safe_mode = packet.safemode_supported != 0 && packet.in_safe_mode != 0;
        result.aux_flags = in_safe_mode ? 1L : 0L;

        std::string detail =
                "A sacrificial child installed temporary [ksu_driver] and KSU_IOCTL_GET_INFO returned version " +
                std::to_string(packet.version) + ".";
        detail += "\nFlags:";
        detail += is_lkm ? " LKM" : " non-LKM";
        detail += is_late_load ? ", late-load" : ", early-load";
        if (is_pr_build) {
            detail += ", PR build";
        }
        if (is_manager) {
            detail += ", manager context";
        }
        detail += "\nFeatures max: " + std::to_string(packet.features);
        if (packet.safemode_supported != 0) {
            detail += "\nSafe mode: ";
            detail += in_safe_mode ? "enabled" : "disabled";
        } else {
            detail += "\nSafe mode: unavailable";
        }

        result.findings.push_back(
                build_finding(
                        "v" + std::to_string(packet.version),
                        detail,
                        Severity::kDanger
                )
        );

        if (in_safe_mode) {
            result.findings.push_back(
                    Finding{
                            .group = "SYSCALL",
                            .label = "KSU safe mode",
                            .value = "Enabled",
                            .detail = "KSU_IOCTL_CHECK_SAFEMODE reported safe mode enabled.",
                            .severity = Severity::kInfo,
                    }
            );
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
