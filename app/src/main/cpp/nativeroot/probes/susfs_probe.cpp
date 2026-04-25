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

#include "nativeroot/probes/susfs_probe.h"

#include <cerrno>
#include <csignal>
#include <sstream>
#include <string>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace duckdetector::nativeroot {

    ProbeResult run_susfs_probe() {
        ProbeResult result;

        const uid_t current_uid = getuid();
        if (current_uid == 0) {
            return result;
        }

        uid_t target_uid = 0;
        if (current_uid >= 10000) {
            target_uid = current_uid > 10000 ? 10000 : static_cast<uid_t>(current_uid - 1);
        } else if (current_uid > 0) {
            target_uid = static_cast<uid_t>(current_uid - 1);
        }
        if (target_uid >= current_uid) {
            return result;
        }

        const pid_t pid = fork();
        if (pid < 0) {
            return result;
        }

        if (pid == 0) {
            const long syscall_result = syscall(__NR_setresuid, target_uid, target_uid, target_uid);
            _exit(syscall_result == 0 ? 100 : 0);
        }

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            return result;
        }

        std::ostringstream detail;
        detail << "Current UID " << current_uid << ", attempted setresuid(" << target_uid << ").";

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) {
            result.flags.kernel_su = true;
            result.flags.susfs = true;
            result.hit_count = 1;
            detail << " Child was killed by SIGKILL instead of returning EPERM.";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "SUSFS side-channel",
                            .value = "SIGKILL",
                            .detail = detail.str(),
                            .severity = Severity::kDanger,
                    }
            );
            return result;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 100) {
            result.hit_count = 1;
            detail << " Child unexpectedly changed UID successfully.";
            result.findings.push_back(
                    Finding{
                            .group = "SIDE_CHANNEL",
                            .label = "setresuid privilege change",
                            .value = "Unexpected success",
                            .detail = detail.str(),
                            .severity = Severity::kDanger,
                    }
            );
        }

        return result;
    }

}  // namespace duckdetector::nativeroot
