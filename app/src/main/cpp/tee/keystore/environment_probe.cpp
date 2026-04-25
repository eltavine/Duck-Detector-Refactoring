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

#include "tee/keystore/environment_probe.h"

#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <array>
#include <cstdio>
#include <sstream>
#include <string>

#include <unistd.h>

#include "tee/common/syscall_facade.h"

namespace ducktee::keystore {
    namespace {

        bool read_tracer_pid() {
            FILE *file = std::fopen("/proc/self/status", "r");
            if (file == nullptr) {
                return false;
            }

            char line[256];
            bool traced = false;
            while (std::fgets(line, sizeof(line), file) != nullptr) {
                if (std::strncmp(line, "TracerPid:", 10) == 0) {
                    traced = std::atoi(line + 10) != 0;
                    break;
                }
            }
            std::fclose(file);
            return traced;
        }

        std::vector<std::string> collect_suspicious_mappings() {
            std::vector<std::string> matches;
            FILE *file = std::fopen("/proc/self/maps", "r");
            if (file == nullptr) {
                return matches;
            }

            constexpr std::array<const char *, 5> kKeywords = {
                    "tricky",
                    "tee_sim",
                    "keybox",
                    "keystore_interceptor",
                    "bootloader_spoofer",
            };

            char line[512];
            while (std::fgets(line, sizeof(line), file) != nullptr) {
                std::string value(line);
                for (const char *keyword: kKeywords) {
                    if (value.find(keyword) != std::string::npos) {
                        value.erase(value.find_last_not_of("\r\n") + 1);
                        matches.push_back(value);
                        break;
                    }
                }
            }
            std::fclose(file);
            return matches;
        }

        std::string measure_timing_summary() {
            constexpr int kIterations = 12;
            constexpr int kAttempts = 3;
            constexpr std::array kBackends = {
                    ducktee::common::SyscallBackend::Libc,
                    ducktee::common::SyscallBackend::Syscall,
                    ducktee::common::SyscallBackend::Asm,
            };

            std::ostringstream builder;
            bool first = true;
            for (const auto backend: kBackends) {
                if (!ducktee::common::backend_available(backend)) {
                    continue;
                }
                std::array<long long, kAttempts> averages{};
                bool backend_ok = true;
                for (int attempt = 0; attempt < kAttempts; ++attempt) {
                    long long total = 0;
                    for (int i = 0; i < kIterations; ++i) {
                        std::uint64_t start = 0;
                        std::uint64_t end = 0;
                        if (!ducktee::common::monotonic_time_ns(backend, &start)) {
                            backend_ok = false;
                            break;
                        }
                        const auto pid_result = ducktee::common::invoke_getpid(backend);
                        if (!pid_result.available || pid_result.value <= 0) {
                            backend_ok = false;
                            break;
                        }
                        if (!ducktee::common::monotonic_time_ns(backend, &end)) {
                            backend_ok = false;
                            break;
                        }
                        total += static_cast<long long>(end >= start ? (end - start) : 0);
                    }
                    if (!backend_ok) {
                        break;
                    }
                    averages[attempt] = total / kIterations;
                }

                if (!first) {
                    builder << ", ";
                }
                first = false;
                builder << ducktee::common::backend_label(backend) << "_ns=";
                if (!backend_ok) {
                    builder << "unavailable";
                    continue;
                }
                const auto minmax = std::minmax_element(averages.begin(), averages.end());
                builder << *minmax.first << "-" << *minmax.second;
            }
            builder << ", attempts=" << kAttempts;
            return builder.str();
        }

    }  // namespace

    EnvironmentSnapshot collect_environment() {
        EnvironmentSnapshot snapshot;
        snapshot.tracing_detected = read_tracer_pid();
        snapshot.page_size = static_cast<int>(::sysconf(_SC_PAGESIZE));
        snapshot.timing_summary = measure_timing_summary();
        snapshot.suspicious_mappings = collect_suspicious_mappings();
        return snapshot;
    }

}  // namespace ducktee::keystore
