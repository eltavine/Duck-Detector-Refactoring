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

#include "kernelcheck/arm64_cpu_identity_probe.h"

#include <cerrno>
#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iomanip>
#include <pthread.h>
#include <sched.h>
#include <sstream>
#include <string_view>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace duckdetector::kernelcheck {

    namespace {

#if defined(__aarch64__)
        pthread_mutex_t g_sigill_mutex = PTHREAD_MUTEX_INITIALIZER;
        thread_local sigjmp_buf *g_sigill_jump_buffer = nullptr;
        struct sigaction g_previous_sigill_action{};

        void forward_sigill(int signal_number, siginfo_t *info, void *context) {
            if ((g_previous_sigill_action.sa_flags & SA_SIGINFO) != 0 &&
                g_previous_sigill_action.sa_sigaction != nullptr) {
                g_previous_sigill_action.sa_sigaction(signal_number, info, context);
                return;
            }

            if (g_previous_sigill_action.sa_handler == SIG_IGN) {
                return;
            }
            if (g_previous_sigill_action.sa_handler != SIG_DFL &&
                g_previous_sigill_action.sa_handler != nullptr) {
                g_previous_sigill_action.sa_handler(signal_number);
                return;
            }

            sigaction(SIGILL, &g_previous_sigill_action, nullptr);
            raise(SIGILL);
        }

        void sigill_handler(int signal_number, siginfo_t *info, void *context) {
            if (g_sigill_jump_buffer != nullptr) {
                siglongjmp(*g_sigill_jump_buffer, 1);
            }
            forward_sigill(signal_number, info, context);
        }

        /**
         * Reads MIDR_EL1 through the kernel's EL0 MRS emulation.
         *
         * This comparison is only meaningful because MIDR_EL1 is the exception among the emulated
         * registers. Documentation/arm64/cpu-feature-registers.rst states that a visible field
         * "holds the system wide safe value for the particular feature (except for MIDR_EL1)", and
         * for MIDR_EL1 specifically that it "will contain the value as available on the CPU where it
         * is fetched and is not a system wide safe value". So this tracks the core the thread is
         * pinned to, which is why the caller sets affinity first -- the same document warns the read
         * is otherwise racy against migration. The ID_AA64* registers must not be used this way:
         * they are sanitised system-wide values and would compare equal on every core by design.
         *
         * SIGILL is still handled because the access is architecturally undefined at EL0 and the
         * emulation is what makes it work; a kernel lacking it delivers the signal instead.
         */
        bool read_midr_safely(std::uint32_t *midr) {
            if (midr == nullptr || pthread_mutex_lock(&g_sigill_mutex) != 0) {
                return false;
            }

            struct sigaction action{};
            action.sa_sigaction = sigill_handler;
            action.sa_flags = SA_SIGINFO;
            sigemptyset(&action.sa_mask);
            if (sigaction(SIGILL, &action, &g_previous_sigill_action) != 0) {
                pthread_mutex_unlock(&g_sigill_mutex);
                return false;
            }

            bool succeeded = false;
            sigjmp_buf jump_buffer;
            g_sigill_jump_buffer = &jump_buffer;
            if (sigsetjmp(jump_buffer, 1) == 0) {
                std::uint64_t value = 0;
                __asm__ volatile("mrs %0, MIDR_EL1" : "=r"(value));
                *midr = static_cast<std::uint32_t>(value);
                succeeded = true;
            }
            g_sigill_jump_buffer = nullptr;
            sigaction(SIGILL, &g_previous_sigill_action, nullptr);
            pthread_mutex_unlock(&g_sigill_mutex);
            return succeeded;
        }
#endif

        std::string read_file(const std::string &path, std::size_t limit = 128 * 1024) {
            const int fd = static_cast<int>(syscall(
                    __NR_openat,
                    AT_FDCWD,
                    path.c_str(),
                    O_RDONLY | O_CLOEXEC,
                    0
            ));
            if (fd < 0) {
                return "";
            }

            std::string content;
            char buffer[4096];
            ssize_t bytes_read = 0;
            while (content.size() < limit &&
                   (bytes_read = syscall(__NR_read, fd, buffer, sizeof(buffer))) > 0) {
                content.append(buffer, static_cast<std::size_t>(bytes_read));
            }
            syscall(__NR_close, fd);
            return content;
        }

        std::string trim_copy(std::string_view value) {
            const std::size_t first = value.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return "";
            }
            const std::size_t last = value.find_last_not_of(" \t\r\n");
            return std::string(value.substr(first, last - first + 1));
        }

        std::optional<std::uint32_t> parse_number(
                const std::string &value,
                int default_base
        ) {
            const std::string trimmed = trim_copy(value);
            if (trimmed.empty()) {
                return std::nullopt;
            }

            char *end = nullptr;
            errno = 0;
            const unsigned long parsed = std::strtoul(trimmed.c_str(), &end, default_base);
            if (errno != 0 || end == trimmed.c_str() || *end != '\0' || parsed > UINT32_MAX) {
                return std::nullopt;
            }
            return static_cast<std::uint32_t>(parsed);
        }

        std::optional<std::uint32_t> read_sysfs_midr(int cpu) {
            const std::string path = "/sys/devices/system/cpu/cpu" + std::to_string(cpu) +
                                     "/regs/identification/midr_el1";
            const std::string raw = trim_copy(read_file(path, 128));
            if (raw.empty()) {
                return std::nullopt;
            }
            const int base = raw.starts_with("0x") || raw.starts_with("0X") ? 0 : 16;
            return parse_number(raw, base);
        }

        struct ProcMidrFields {
            std::optional<std::uint32_t> implementer;
            std::optional<std::uint32_t> variant;
            std::optional<std::uint32_t> part;
            std::optional<std::uint32_t> revision;

            std::optional<std::uint32_t> to_midr() const {
                if (!implementer || !variant || !part || !revision ||
                    *implementer > 0xff || *variant > 0xf || *part > 0xfff || *revision > 0xf) {
                    return std::nullopt;
                }
                return (*implementer << 24U) |
                       (*variant << 20U) |
                       (*part << 4U) |
                       *revision;
            }
        };

        std::optional<std::uint32_t> read_proc_cpuinfo_midr(int target_cpu) {
            std::istringstream input(read_file("/proc/cpuinfo"));
            std::string line;
            int current_cpu = -1;
            ProcMidrFields fields;

            const auto finish_block = [&]() -> std::optional<std::uint32_t> {
                return current_cpu == target_cpu ? fields.to_midr() : std::nullopt;
            };

            while (std::getline(input, line)) {
                if (trim_copy(line).empty()) {
                    if (const auto midr = finish_block()) {
                        return midr;
                    }
                    current_cpu = -1;
                    fields = ProcMidrFields{};
                    continue;
                }

                const std::size_t separator = line.find(':');
                if (separator == std::string::npos) {
                    continue;
                }
                const std::string key = trim_copy(std::string_view(line).substr(0, separator));
                const std::string value = trim_copy(std::string_view(line).substr(separator + 1));
                if (key == "processor") {
                    const auto parsed = parse_number(value, 10);
                    current_cpu = parsed ? static_cast<int>(*parsed) : -1;
                } else if (current_cpu == target_cpu && key == "CPU implementer") {
                    fields.implementer = parse_number(value, 0);
                } else if (current_cpu == target_cpu && key == "CPU variant") {
                    fields.variant = parse_number(value, 0);
                } else if (current_cpu == target_cpu && key == "CPU part") {
                    fields.part = parse_number(value, 0);
                } else if (current_cpu == target_cpu && key == "CPU revision") {
                    fields.revision = parse_number(value, 0);
                }
            }
            return finish_block();
        }

        void collect_cached_identity(CpuIdentityObservation *observation) {
            observation->cached_midr = read_sysfs_midr(observation->cpu);
            if (observation->cached_midr) {
                observation->cached_source = CachedCpuIdentitySource::Sysfs;
                return;
            }

            observation->cached_midr = read_proc_cpuinfo_midr(observation->cpu);
            if (observation->cached_midr) {
                observation->cached_source = CachedCpuIdentitySource::ProcCpuinfo;
            }
        }

        const char *status_name(CpuIdentityProbeStatus status) {
            switch (status) {
                case CpuIdentityProbeStatus::Completed:
                    return "COMPLETED";
                case CpuIdentityProbeStatus::UnsupportedAbi:
                    return "UNSUPPORTED_ABI";
                case CpuIdentityProbeStatus::AffinityUnavailable:
                    return "AFFINITY_UNAVAILABLE";
                case CpuIdentityProbeStatus::CpuidEmulationUnavailable:
                    return "CPUID_EMULATION_UNAVAILABLE";
            }
            return "AFFINITY_UNAVAILABLE";
        }

        const char *source_name(CachedCpuIdentitySource source) {
            switch (source) {
                case CachedCpuIdentitySource::None:
                    return "NONE";
                case CachedCpuIdentitySource::Sysfs:
                    return "SYSFS";
                case CachedCpuIdentitySource::ProcCpuinfo:
                    return "PROC_CPUINFO";
            }
            return "NONE";
        }

        std::string format_midr(const std::optional<std::uint32_t> &midr) {
            if (!midr) {
                return "NA";
            }
            std::ostringstream output;
            output << std::hex << std::nouppercase << std::setw(8) << std::setfill('0') << *midr;
            return output.str();
        }

    }  // namespace

    CpuIdentityProbeResult collect_arm64_cpu_identity() {
        CpuIdentityProbeResult result;
#if defined(__aarch64__)
        cpu_set_t original_affinity;
        CPU_ZERO(&original_affinity);
        if (sched_getaffinity(0, sizeof(original_affinity), &original_affinity) != 0) {
            result.status = CpuIdentityProbeStatus::AffinityUnavailable;
            return result;
        }

        // Documentation/arm64/cpu-feature-registers.rst: reading MIDR_EL1 from EL0 works only
        // through the kernel's MRS emulation, which is advertised by HWCAP_CPUID; where it is
        // absent the access stays undefined and is delivered as SIGILL. Consulting the capability
        // bit keeps "this kernel exposes no CPUID emulation" distinct from "the read failed", and
        // avoids provoking a SIGILL on every core to rediscover what the kernel already states.
        const bool cpuid_emulation_available = (getauxval(AT_HWCAP) & HWCAP_CPUID) != 0;
        result.status = cpuid_emulation_available
                        ? CpuIdentityProbeStatus::Completed
                        : CpuIdentityProbeStatus::CpuidEmulationUnavailable;

        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (!CPU_ISSET(cpu, &original_affinity)) {
                continue;
            }

            CpuIdentityObservation observation;
            observation.cpu = cpu;
            cpu_set_t target_affinity;
            CPU_ZERO(&target_affinity);
            CPU_SET(cpu, &target_affinity);
            observation.affinity_succeeded =
                    sched_setaffinity(0, sizeof(target_affinity), &target_affinity) == 0;
            if (observation.affinity_succeeded) {
                // The cached identity is still collected without MRS emulation, so the report can
                // show what each core reports even when no register read is possible.
                collect_cached_identity(&observation);
                if (cpuid_emulation_available) {
                    std::uint32_t mrs_midr = 0;
                    if (read_midr_safely(&mrs_midr)) {
                        observation.mrs_midr = mrs_midr;
                    }
                }
            }
            result.observations.push_back(observation);
        }

        sched_setaffinity(0, sizeof(original_affinity), &original_affinity);
#else
        result.status = CpuIdentityProbeStatus::UnsupportedAbi;
#endif
        return result;
    }

    std::string encode_arm64_cpu_identity(const CpuIdentityProbeResult &result) {
        std::ostringstream output;
        output << "CPU_IDENTITY_STATUS=" << status_name(result.status) << '\n';
        for (const CpuIdentityObservation &observation: result.observations) {
            output << "CPU_IDENTITY="
                   << observation.cpu << '\t'
                   << (observation.affinity_succeeded ? "1" : "0") << '\t'
                   << source_name(observation.cached_source) << '\t'
                   << format_midr(observation.cached_midr) << '\t'
                   << format_midr(observation.mrs_midr) << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::kernelcheck
