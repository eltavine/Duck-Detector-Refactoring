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

#include "tee/trickystore/trickystore_probe.h"

#include <algorithm>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "tee/common/syscall_facade.h"
#include "tee/common/timing_stats.h"

namespace ducktee::trickystore {
    namespace {

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)

        struct binder_write_read {
            signed long write_size;
            signed long write_consumed;
            unsigned long write_buffer;
            signed long read_size;
            signed long read_consumed;
            unsigned long read_buffer;
        };

        struct binder_version {
            signed long protocol_version;
        };

        struct binder_transaction_data {
            union {
                unsigned int handle;
                void *ptr;
            } target;
            void *cookie;
            unsigned int code;
            unsigned int flags;
            int sender_pid;
            unsigned int sender_euid;
            unsigned long data_size;
            unsigned long offsets_size;
            union {
                struct {
                    unsigned long buffer;
                    unsigned long offsets;
                } ptr;
                unsigned char buf[8];
            } data;
        };

        struct MethodSnapshot {
            bool detected = false;
            std::string detail;
            std::vector<std::string> findings;
            int honeypot_run_count = 0;
            int honeypot_suspicious_run_count = 0;
            std::uint64_t honeypot_median_gap_ns = 0;
            std::uint64_t honeypot_gap_mad_ns = 0;
            std::uint64_t honeypot_median_noise_floor_ns = 0;
            int honeypot_median_ratio_percent = 0;
            std::string timer_source = "unknown";
            std::string timer_fallback_reason;
            std::string affinity_status = "not_requested";
        };

        struct LibInfo {
            uintptr_t base = 0;
            std::string path;
            bool found = false;
        };

        struct MapAccess {
            bool found = false;
            bool readable = false;
        };

        constexpr int kHoneypotIterations = 40;
        constexpr std::uint64_t kHoneypotBaseGapThresholdNs = 10'000ULL;
        constexpr std::uint64_t kHoneypotNoiseMultiplier = 6ULL;
        constexpr std::uint64_t kHoneypotRatioThresholdPercent = 150ULL;
        constexpr int kRepeatedProbeAttempts = 3;
        constexpr std::array<ducktee::common::SyscallBackend, 3> kIoctlBackends = {
                ducktee::common::SyscallBackend::Libc,
                ducktee::common::SyscallBackend::Syscall,
                ducktee::common::SyscallBackend::Asm,
        };

        struct IoctlBackendObservation {
            ducktee::common::SyscallBackend backend = ducktee::common::SyscallBackend::Libc;
            long result = -1;
            int error_number = 0;
            int protocol_version = 0;
        };

        struct HoneypotTimingPath {
            ducktee::common::SyscallBackend backend = ducktee::common::SyscallBackend::Libc;
            bool available = false;
            std::vector<std::uint64_t> samples;
            ducktee::common::SampleStats stats;
            std::string failure;

            [[nodiscard]] std::uint64_t median_ns() const {
                return stats.median_ns;
            }
        };

        struct HoneypotRunSummary {
            bool suspicious = false;
            bool libc_available = false;
            bool lower_found = false;
            bool stable_lower_paths = false;
            std::uint64_t libc_median_ns = 0;
            std::uint64_t fastest_lower_median_ns = 0;
            std::uint64_t gap_ns = 0;
            std::uint64_t noise_floor_ns = 0;
            std::uint64_t ratio_percent = 0;
            std::string path_summary;
        };

        int raw_open(const char *path, int flags) {
#if defined(__NR_openat)
            return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
#else
            return open(path, flags);
#endif
        }

        int open_binder_device() {
            int fd = raw_open("/dev/binder", O_RDWR | O_CLOEXEC);
            if (fd < 0) {
                fd = raw_open("/dev/vndbinder", O_RDWR | O_CLOEXEC);
            }
            return fd;
        }

        std::vector<ducktee::common::SyscallBackend> available_backends() {
            std::vector<ducktee::common::SyscallBackend> backends;
            for (const auto backend: kIoctlBackends) {
                if (ducktee::common::backend_available(backend)) {
                    backends.push_back(backend);
                }
            }
            return backends;
        }

        std::vector<ducktee::common::SyscallBackend> rotated_available_backends(const int attempt) {
            auto backends = available_backends();
            if (backends.empty()) {
                return backends;
            }
            const auto rotation = static_cast<std::size_t>(attempt) % backends.size();
            std::rotate(backends.begin(), backends.begin() + rotation, backends.end());
            return backends;
        }

        ducktee::common::SyscallCallResult call_ioctl_backend(
                const ducktee::common::SyscallBackend backend,
                const int fd,
                const unsigned long request,
                void *arg
        ) {
            return ducktee::common::invoke_ioctl(backend, fd, request, arg);
        }

        std::string format_backend_observation(const IoctlBackendObservation &observation) {
            std::ostringstream builder;
            builder << ducktee::common::backend_label(observation.backend)
                    << "(ret=" << observation.result
                    << ", errno=" << observation.error_number
                    << ", version=" << observation.protocol_version << ")";
            return builder.str();
        }

        bool backend_samples_aligned(
                const IoctlBackendObservation &reference,
                const IoctlBackendObservation &candidate
        ) {
            return reference.result == candidate.result &&
                   reference.error_number == candidate.error_number &&
                   reference.protocol_version == candidate.protocol_version;
        }

        void prepare_honeypot_payload(
                std::uint8_t *write_buffer,
                binder_write_read *bwr,
                std::uint8_t *fake_data
        ) {
            std::memset(write_buffer, 0, 256);
            const std::uint32_t command = BC_TRANSACTION;
            std::memcpy(write_buffer, &command, sizeof(command));

            binder_transaction_data transaction{};
            transaction.target.handle = 0;
            transaction.code = 1;
            transaction.data_size = 64;
            transaction.offsets_size = 0;

            std::memset(fake_data, 0, 64);
            const char *descriptor = "android.security.keystore2";
            std::memcpy(fake_data, descriptor, std::strlen(descriptor));
            transaction.data.ptr.buffer = reinterpret_cast<unsigned long>(fake_data);
            transaction.data.ptr.offsets = 0;

            std::memcpy(write_buffer + sizeof(command), &transaction, sizeof(transaction));

            std::memset(bwr, 0, sizeof(*bwr));
            bwr->write_buffer = reinterpret_cast<unsigned long>(write_buffer);
            bwr->write_size = sizeof(command) + sizeof(transaction);
        }

        bool collect_honeypot_backend_samples(
                const int binder_fd,
                const ducktee::common::LocalTimerSelection &timer,
                HoneypotTimingPath *path
        ) {
            if (path == nullptr ||
                !ducktee::common::backend_available(path->backend)) {
                return false;
            }

            std::uint8_t write_buffer[256];
            std::uint8_t fake_data[64];
            binder_write_read bwr{};
            prepare_honeypot_payload(write_buffer, &bwr, fake_data);

            for (int index = 0; index < kHoneypotIterations; ++index) {
                bwr.write_consumed = 0;
                std::uint64_t start = 0;
                std::uint64_t end = 0;
                if (!ducktee::common::local_timer_now_ns(timer, &start)) {
                    path->failure = std::string("Failed to read ")
                                    + timer.source_label
                                    + " before ioctl.";
                    return false;
                }
                const auto result = call_ioctl_backend(path->backend, binder_fd, BINDER_WRITE_READ,
                                                       &bwr);
                if (!result.available) {
                    path->failure = std::string("Backend ")
                                    + ducktee::common::backend_label(path->backend)
                                    + " was unavailable for binder honeypot timing.";
                    return false;
                }
                if (!ducktee::common::local_timer_now_ns(timer, &end)) {
                    path->failure = std::string("Failed to read ")
                                    + timer.source_label
                                    + " after ioctl.";
                    return false;
                }
                path->samples.push_back(end >= start ? (end - start) : 0);
            }

            path->stats = ducktee::common::summarize_samples(path->samples);
            path->available = path->stats.available;
            return path->available;
        }

        bool lower_paths_are_stable(const std::vector<HoneypotTimingPath> &paths) {
            std::vector<std::uint64_t> medians;
            for (const auto &path: paths) {
                if (path.backend == ducktee::common::SyscallBackend::Libc || !path.available) {
                    continue;
                }
                medians.push_back(path.median_ns());
            }
            if (medians.size() < 2) {
                return true;
            }
            const auto minmax = std::minmax_element(medians.begin(), medians.end());
            const auto fastest = std::max<std::uint64_t>(1, *minmax.first);
            const auto slowest = *minmax.second;
            return slowest <= fastest + 25'000ULL && slowest <= fastest * 3ULL / 2ULL;
        }

        std::string describe_honeypot_path(const HoneypotTimingPath &path) {
            std::ostringstream builder;
            builder << ducktee::common::backend_label(path.backend) << "=";
            if (path.available) {
                builder << "med" << path.stats.median_ns << "ns";
                builder << "/mad" << path.stats.mad_ns << "ns";
                builder << "/p95" << path.stats.p95_ns << "ns";
            } else if (!path.failure.empty()) {
                builder << "unavailable(" << path.failure << ")";
            } else {
                builder << "unavailable";
            }
            return builder.str();
        }

        std::string describe_honeypot_paths(const std::vector<HoneypotTimingPath> &paths) {
            std::ostringstream builder;
            bool first = true;
            for (const auto &path: paths) {
                if (!first) {
                    builder << ", ";
                }
                first = false;
                builder << describe_honeypot_path(path);
            }
            return builder.str();
        }

        HoneypotRunSummary analyze_honeypot_paths(const std::vector<HoneypotTimingPath> &paths) {
            HoneypotRunSummary summary;
            summary.path_summary = describe_honeypot_paths(paths);

            const auto libc_it = std::find_if(
                    paths.begin(),
                    paths.end(),
                    [](const HoneypotTimingPath &path) {
                        return path.backend == ducktee::common::SyscallBackend::Libc;
                    }
            );
            const HoneypotTimingPath *fastest_lower_path = nullptr;
            for (const auto &path: paths) {
                if (!path.available || path.backend == ducktee::common::SyscallBackend::Libc) {
                    continue;
                }
                if (fastest_lower_path == nullptr || path.median_ns() < fastest_lower_path->median_ns()) {
                    fastest_lower_path = &path;
                }
            }

            summary.stable_lower_paths = lower_paths_are_stable(paths);
            summary.libc_available = libc_it != paths.end() && libc_it->available;
            summary.lower_found = fastest_lower_path != nullptr;
            summary.libc_median_ns = summary.libc_available ? libc_it->median_ns() : 0;
            summary.fastest_lower_median_ns =
                    summary.lower_found ? fastest_lower_path->median_ns() : 0;

            if (!summary.libc_available ||
                !summary.lower_found ||
                summary.libc_median_ns <= summary.fastest_lower_median_ns) {
                return summary;
            }

            summary.gap_ns = summary.libc_median_ns - summary.fastest_lower_median_ns;
            const std::uint64_t libc_mad = libc_it->stats.mad_ns;
            const std::uint64_t lower_mad = fastest_lower_path->stats.mad_ns;
            summary.noise_floor_ns = std::max({
                    static_cast<std::uint64_t>(kHoneypotBaseGapThresholdNs),
                    static_cast<std::uint64_t>(libc_mad * 4ULL),
                    static_cast<std::uint64_t>(lower_mad * kHoneypotNoiseMultiplier),
            });
            summary.ratio_percent =
                    (summary.libc_median_ns * 100ULL) / std::max<std::uint64_t>(1ULL,
                                                                                summary.fastest_lower_median_ns);
            summary.suspicious = summary.stable_lower_paths &&
                                 summary.gap_ns > summary.noise_floor_ns &&
                                 summary.ratio_percent >= kHoneypotRatioThresholdPercent;
            return summary;
        }

        LibInfo find_library(const std::string &needle) {
            LibInfo info;
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) {
                return info;
            }

            std::string line;
            while (std::getline(maps, line)) {
                if (line.find(needle) == std::string::npos) {
                    continue;
                }
                const std::size_t dash = line.find('-');
                if (dash == std::string::npos) {
                    continue;
                }

                uintptr_t address = 0;
                for (std::size_t index = 0; index < dash; ++index) {
                    const char ch = line[index];
                    address <<= 4;
                    if (ch >= '0' && ch <= '9') {
                        address |= static_cast<uintptr_t>(ch - '0');
                    } else if (ch >= 'a' && ch <= 'f') {
                        address |= static_cast<uintptr_t>(ch - 'a' + 10);
                    } else if (ch >= 'A' && ch <= 'F') {
                        address |= static_cast<uintptr_t>(ch - 'A' + 10);
                    }
                }

                const std::size_t path_start = line.find('/');
                if (path_start == std::string::npos) {
                    continue;
                }

                info.base = address;
                info.path = line.substr(path_start);
                while (!info.path.empty() && info.path.back() <= ' ') {
                    info.path.pop_back();
                }
                info.found = true;
                break;
            }
            return info;
        }

        MapAccess find_map_access_for_address(const uintptr_t address) {
            MapAccess access;
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) {
                return access;
            }

            std::string line;
            while (std::getline(maps, line)) {
                unsigned long long start = 0;
                unsigned long long end = 0;
                char perms[5] = {};
                if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end, perms) != 3) {
                    continue;
                }
                if (address < start || address >= end) {
                    continue;
                }
                access.found = true;
                access.readable = perms[0] == 'r';
                return access;
            }
            return access;
        }

        bool maps_contain_trickystore(std::vector<std::string> *findings) {
            std::ifstream maps("/proc/self/maps");
            if (!maps.is_open()) {
                return false;
            }

            bool matched = false;
            std::string line;
            while (std::getline(maps, line)) {
                if (line.find("tricky") != std::string::npos ||
                    line.find("keystore_interceptor") != std::string::npos) {
                    matched = true;
                    if (findings != nullptr) {
                        findings->push_back(line);
                    }
                }
            }
            return matched;
        }

#if defined(__LP64__)
        using ElfWord_Ehdr = Elf64_Ehdr;
        using ElfWord_Phdr = Elf64_Phdr;
        using ElfWord_Dyn = Elf64_Dyn;
        using ElfWord_Sym = Elf64_Sym;
        using ElfWord_Rela = Elf64_Rela;
        using ElfWord_Addr = Elf64_Addr;
#define DUCK_ELF_R_SYM(value) ELF64_R_SYM(value)
#define DUCK_ELF_R_TYPE(value) ELF64_R_TYPE(value)
#define DUCK_R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#if defined(__x86_64__)
#undef DUCK_R_JUMP_SLOT
#define DUCK_R_JUMP_SLOT R_X86_64_JUMP_SLOT
#endif
#else
        using ElfWord_Ehdr = Elf32_Ehdr;
        using ElfWord_Phdr = Elf32_Phdr;
        using ElfWord_Dyn = Elf32_Dyn;
        using ElfWord_Sym = Elf32_Sym;
        using ElfWord_Rela = Elf32_Rel;
        using ElfWord_Addr = Elf32_Addr;
#define DUCK_ELF_R_SYM(value) ELF32_R_SYM(value)
#define DUCK_ELF_R_TYPE(value) ELF32_R_TYPE(value)
#define DUCK_R_JUMP_SLOT R_ARM_JUMP_SLOT
#if defined(__i386__)
#undef DUCK_R_JUMP_SLOT
#define DUCK_R_JUMP_SLOT R_386_JMP_SLOT
#endif
#endif

        MethodSnapshot detect_got_ioctl_hook() {
            MethodSnapshot snapshot;

            void *real_ioctl = dlsym(RTLD_DEFAULT, "ioctl");
            if (real_ioctl == nullptr) {
                snapshot.detail = "Failed to resolve ioctl via dlsym.";
                return snapshot;
            }

            const LibInfo binder = find_library("libbinder.so");
            if (!binder.found || binder.path.empty()) {
                snapshot.detail = "libbinder.so not found in process maps.";
                return snapshot;
            }

            const int fd = raw_open(binder.path.c_str(), O_RDONLY | O_CLOEXEC);
            if (fd < 0) {
                snapshot.detail = "Failed to open libbinder.so for GOT inspection.";
                return snapshot;
            }

            ElfWord_Ehdr ehdr{};
            if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
                std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
                close(fd);
                snapshot.detail = "Failed to read a valid ELF header from libbinder.so.";
                return snapshot;
            }

            std::vector<ElfWord_Phdr> phdrs(ehdr.e_phnum);
            lseek(fd, ehdr.e_phoff, SEEK_SET);
            const auto phdr_bytes = sizeof(ElfWord_Phdr) * static_cast<std::size_t>(ehdr.e_phnum);
            if (read(fd, phdrs.data(), phdr_bytes) != static_cast<ssize_t>(phdr_bytes)) {
                close(fd);
                snapshot.detail = "Failed to read libbinder.so program headers.";
                return snapshot;
            }
            close(fd);

            ElfWord_Addr dyn_vaddr = 0;
            for (const auto &phdr: phdrs) {
                if (phdr.p_type == PT_DYNAMIC) {
                    dyn_vaddr = phdr.p_vaddr;
                    break;
                }
            }
            if (dyn_vaddr == 0) {
                snapshot.detail = "PT_DYNAMIC segment missing from libbinder.so.";
                return snapshot;
            }

            auto *dyn_base = reinterpret_cast<ElfWord_Dyn *>(binder.base + dyn_vaddr);
            ElfWord_Addr jmprel = 0;
            ElfWord_Addr pltrelsz = 0;
            ElfWord_Addr symtab_addr = 0;
            ElfWord_Addr strtab_addr = 0;

            for (auto *dyn = dyn_base; dyn->d_tag != DT_NULL; ++dyn) {
                switch (dyn->d_tag) {
                    case DT_JMPREL:
                        jmprel = dyn->d_un.d_ptr;
                        break;
                    case DT_PLTRELSZ:
                        pltrelsz = dyn->d_un.d_val;
                        break;
                    case DT_SYMTAB:
                        symtab_addr = dyn->d_un.d_ptr;
                        break;
                    case DT_STRTAB:
                        strtab_addr = dyn->d_un.d_ptr;
                        break;
                    default:
                        break;
                }
            }

            if (jmprel != 0 && jmprel < binder.base) {
                jmprel += binder.base;
            }
            if (symtab_addr != 0 && symtab_addr < binder.base) {
                symtab_addr += binder.base;
            }
            if (strtab_addr != 0 && strtab_addr < binder.base) {
                strtab_addr += binder.base;
            }

            if (jmprel == 0 || pltrelsz == 0 || symtab_addr == 0 || strtab_addr == 0) {
                snapshot.detail = "libbinder.so was missing PLT relocation metadata for ioctl.";
                return snapshot;
            }

            auto *rels = reinterpret_cast<ElfWord_Rela *>(jmprel);
            auto *symtab = reinterpret_cast<ElfWord_Sym *>(symtab_addr);
            auto *strtab = reinterpret_cast<const char *>(strtab_addr);
            const std::size_t rel_count = pltrelsz / sizeof(ElfWord_Rela);

            for (std::size_t index = 0; index < rel_count; ++index) {
                const unsigned long sym_index = DUCK_ELF_R_SYM(rels[index].r_info);
                const unsigned long rel_type = DUCK_ELF_R_TYPE(rels[index].r_info);
                if (rel_type != DUCK_R_JUMP_SLOT) {
                    continue;
                }

                const char *symbol_name = strtab + symtab[sym_index].st_name;
                if (std::strcmp(symbol_name, "ioctl") != 0) {
                    continue;
                }

                auto *got_entry = reinterpret_cast<void **>(binder.base + rels[index].r_offset);
                void *got_value = *got_entry;
                if (got_value != real_ioctl) {
                    snapshot.detected = true;
                    Dl_info dl_info{};
                    std::string hook_library = "unknown";
                    if (dladdr(got_value, &dl_info) && dl_info.dli_fname != nullptr) {
                        hook_library = dl_info.dli_fname;
                    }
                    std::ostringstream builder;
                    builder << "libbinder.so ioctl GOT entry resolved to " << got_value
                            << " instead of libc ioctl " << real_ioctl
                            << " (hook library: " << hook_library << ").";
                    snapshot.findings.push_back(builder.str());
                    snapshot.detail = "GOT hook detected on ioctl in libbinder.so.";
                } else {
                    snapshot.detail = "libbinder.so ioctl GOT entry matched libc.";
                }
                return snapshot;
            }

            snapshot.detail = "ioctl relocation was not found in libbinder.so.";
            return snapshot;
        }

        MethodSnapshot run_single_syscall_ioctl_mismatch_probe() {
            MethodSnapshot snapshot;
            const int binder_fd = open_binder_device();
            if (binder_fd < 0) {
                snapshot.detail = "Cannot open binder device for ioctl backend comparison.";
                return snapshot;
            }

            std::vector<IoctlBackendObservation> observations;
            for (const auto backend: available_backends()) {
                binder_version version{};
                const auto result = call_ioctl_backend(backend, binder_fd, BINDER_VERSION,
                                                       &version);
                if (!result.available) {
                    continue;
                }
                observations.push_back(IoctlBackendObservation{
                        .backend = backend,
                        .result = result.value,
                        .error_number = result.error_number,
                        .protocol_version = static_cast<int>(version.protocol_version),
                });
            }
            close(binder_fd);

            if (observations.size() < 2) {
                snapshot.detail = "Fewer than two ioctl backends were available for binder comparison.";
                return snapshot;
            }

            const auto &reference = observations.front();
            for (std::size_t index = 1; index < observations.size(); ++index) {
                if (backend_samples_aligned(reference, observations[index])) {
                    continue;
                }
                snapshot.detected = true;
                std::ostringstream builder;
                builder << "Binder version query diverged across backends: "
                        << format_backend_observation(reference) << " vs "
                        << format_backend_observation(observations[index]) << ".";
                snapshot.findings.push_back(builder.str());
                snapshot.detail = "Binder version query returned different results across libc/syscall/asm backends.";
                return snapshot;
            }

            std::ostringstream builder;
            builder << "Binder version query aligned across ";
            for (std::size_t index = 0; index < observations.size(); ++index) {
                if (index > 0) {
                    builder << ", ";
                }
                builder << ducktee::common::backend_label(observations[index].backend);
            }
            builder << " backends.";
            snapshot.detail = builder.str();
            return snapshot;
        }

        MethodSnapshot detect_syscall_ioctl_mismatch() {
            MethodSnapshot snapshot;
            int hit_count = 0;
            std::string last_detail;

            for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
                const MethodSnapshot single = run_single_syscall_ioctl_mismatch_probe();
                if (!single.detail.empty()) {
                    last_detail = single.detail;
                }
                if (!single.detected) {
                    continue;
                }
                ++hit_count;
                if (snapshot.findings.empty()) {
                    snapshot.findings = single.findings;
                }
            }

            snapshot.detected = hit_count >= 2;
            std::ostringstream builder;
            if (snapshot.detected) {
                builder << "Binder version ioctl diverged on " << hit_count
                        << "/" << kRepeatedProbeAttempts << " backend-comparison probes.";
                snapshot.detail = builder.str();
            } else {
                builder << "Binder version ioctl stayed aligned across "
                        << kRepeatedProbeAttempts << " backend-comparison probes";
                if (hit_count > 0) {
                    builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                            << " suspicious run).";
                } else {
                    builder << ".";
                }
                if (!last_detail.empty()) {
                    builder << " " << last_detail;
                }
                snapshot.detail = builder.str();
            }
            return snapshot;
        }

        MethodSnapshot detect_ioctl_inline_hook() {
            MethodSnapshot snapshot;

            void *ioctl_addr = dlsym(RTLD_DEFAULT, "ioctl");
            if (ioctl_addr == nullptr) {
                snapshot.detail = "Failed to resolve ioctl for inline hook inspection.";
                return snapshot;
            }

            Dl_info ioctl_info{};
            if (!dladdr(ioctl_addr, &ioctl_info) || ioctl_info.dli_fname == nullptr) {
                snapshot.detail = "Failed to resolve the backing library for ioctl.";
                return snapshot;
            }

            const MapAccess ioctl_map =
                    find_map_access_for_address(reinterpret_cast<uintptr_t>(ioctl_addr));
            if (!ioctl_map.found || !ioctl_map.readable) {
                snapshot.detail =
                        "Skipped ioctl inline hook inspection because the resolved code page is not readable.";
                return snapshot;
            }

            std::uint8_t memory_prologue[16];
            std::memcpy(memory_prologue, ioctl_addr, sizeof(memory_prologue));

            const LibInfo lib_info = find_library(ioctl_info.dli_fname);
            if (!lib_info.found) {
                snapshot.detail = "Could not locate ioctl library in process maps.";
                return snapshot;
            }

            const int fd = raw_open(ioctl_info.dli_fname, O_RDONLY | O_CLOEXEC);
            bool compared_on_disk = false;
            if (fd >= 0) {
                ElfWord_Ehdr ehdr{};
                if (read(fd, &ehdr, sizeof(ehdr)) == sizeof(ehdr) &&
                    std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
                    std::vector<ElfWord_Phdr> phdrs(ehdr.e_phnum);
                    lseek(fd, ehdr.e_phoff, SEEK_SET);
                    const auto phdr_bytes =
                            sizeof(ElfWord_Phdr) * static_cast<std::size_t>(ehdr.e_phnum);
                    if (read(fd, phdrs.data(), phdr_bytes) == static_cast<ssize_t>(phdr_bytes)) {
                        const uintptr_t ioctl_va =
                                reinterpret_cast<uintptr_t>(ioctl_addr) - lib_info.base;
                        for (const auto &phdr: phdrs) {
                            if (phdr.p_type != PT_LOAD) {
                                continue;
                            }
                            if (ioctl_va >= phdr.p_vaddr &&
                                ioctl_va < phdr.p_vaddr + phdr.p_filesz) {
                                const uintptr_t file_offset =
                                        phdr.p_offset + (ioctl_va - phdr.p_vaddr);
                                std::uint8_t disk_prologue[16];
                                lseek(fd, static_cast<off_t>(file_offset), SEEK_SET);
                                if (read(fd, disk_prologue, sizeof(disk_prologue)) ==
                                    sizeof(disk_prologue)) {
                                    compared_on_disk = true;
                                    if (!ducktee::common::bytes_equal(memory_prologue,
                                                                      disk_prologue,
                                                                      sizeof(memory_prologue))) {
                                        snapshot.detected = true;
                                        std::ostringstream builder;
                                        builder
                                                << "In-memory ioctl prologue differed from the on-disk image.";
                                        snapshot.findings.push_back(builder.str());
                                        snapshot.detail = "Inline hook detected on ioctl.";
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                close(fd);
            }

#if defined(__aarch64__)
            if (!snapshot.detected) {
                auto* instructions = reinterpret_cast<const std::uint32_t*>(ioctl_addr);
                for (int index = 0; index < 4; ++index) {
                    const std::uint32_t word = instructions[index];
                    if ((word & 0xFC000000U) == 0x14000000U && index == 0) {
                        const std::int32_t imm26 = static_cast<std::int32_t>(word << 6) >> 6;
                        const uintptr_t target = reinterpret_cast<uintptr_t>(&instructions[index]) + static_cast<uintptr_t>(imm26 * 4);
                        Dl_info target_info{};
                        if (dladdr(reinterpret_cast<void*>(target), &target_info) &&
                            target_info.dli_fname != nullptr &&
                            std::string(target_info.dli_fname) != std::string(ioctl_info.dli_fname)) {
                            snapshot.detected = true;
                            snapshot.findings.push_back("ioctl begins with an unconditional branch into another library.");
                            snapshot.detail = "Inline hook detected via external branch trampoline.";
                            break;
                        }
                    }
                    if ((word & 0xFFFFFC1FU) == 0xD61F0000U && index < 2) {
                        snapshot.detected = true;
                        snapshot.findings.push_back("ioctl prologue contained a BR register jump.");
                        snapshot.detail = "Inline hook detected via BR trampoline.";
                        break;
                    }
                }
            }
#endif

            if (!snapshot.detected) {
                snapshot.detail = compared_on_disk
                                  ? "ioctl prologue matched the on-disk image."
                                  : "Could not compare the ioctl prologue with the on-disk image.";
            }
            return snapshot;
        }

        MethodSnapshot run_single_ioctl_honeypot_probe(const int attempt) {
            MethodSnapshot snapshot;
            ducktee::common::LocalTimerSelection timer;
            (void) ducktee::common::select_preferred_local_timer(true, &timer);
            snapshot.timer_source = timer.source_label;
            snapshot.timer_fallback_reason = timer.fallback_reason;
            snapshot.affinity_status = timer.affinity_status;

            const int binder_fd = open_binder_device();
            if (binder_fd < 0) {
                snapshot.detail = "Cannot open binder device for honeypot timing.";
                return snapshot;
            }

            void *mapped = mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, binder_fd, 0);
            if (mapped == MAP_FAILED) {
                close(binder_fd);
                snapshot.detail = "Cannot mmap binder device for honeypot timing.";
                return snapshot;
            }

            std::vector<HoneypotTimingPath> paths;
            for (const auto backend: rotated_available_backends(attempt)) {
                HoneypotTimingPath path;
                path.backend = backend;
                (void) collect_honeypot_backend_samples(binder_fd, timer, &path);
                paths.push_back(std::move(path));
            }

            munmap(mapped, 4096);
            close(binder_fd);

            const HoneypotRunSummary run = analyze_honeypot_paths(paths);
            snapshot.honeypot_run_count = 1;
            snapshot.honeypot_suspicious_run_count = run.suspicious ? 1 : 0;
            snapshot.honeypot_median_gap_ns = run.gap_ns;
            snapshot.honeypot_median_noise_floor_ns = run.noise_floor_ns;
            snapshot.honeypot_median_ratio_percent = static_cast<int>(run.ratio_percent);

            if (run.suspicious) {
                snapshot.detected = true;
                std::ostringstream builder;
                builder
                        << "Keystore-style binder ioctl median timing diverged across redundant backends: "
                        << run.path_summary
                        << ". gap=" << run.gap_ns << "ns"
                        << ", noise_floor=" << run.noise_floor_ns << "ns"
                        << ", ratio=" << run.ratio_percent << "%"
                        << ". timer=" << snapshot.timer_source
                        << ", affinity=" << snapshot.affinity_status;
                if (!snapshot.timer_fallback_reason.empty()) {
                    builder << ", fallback=" << snapshot.timer_fallback_reason;
                }
                builder << ".";
                snapshot.findings.push_back(builder.str());
                snapshot.detail = "Keystore-style binder honeypot found a libc-vs-lower-path timing anomaly.";
            } else {
                std::ostringstream builder;
                builder
                        << "Keystore-style binder honeypot timing stayed within normal bounds across redundant backends. "
                        << run.path_summary
                        << " gap=" << run.gap_ns << "ns"
                        << ", noise_floor=" << run.noise_floor_ns << "ns"
                        << ", ratio=" << run.ratio_percent << "%"
                        << " timer=" << snapshot.timer_source
                        << ", affinity=" << snapshot.affinity_status;
                if (!snapshot.timer_fallback_reason.empty()) {
                    builder << ", fallback=" << snapshot.timer_fallback_reason;
                }
                builder << ".";
                if (!run.stable_lower_paths) {
                    builder
                            << " Lower-level syscall and asm paths were not stable enough to escalate.";
                }
                snapshot.detail = builder.str();
            }
            return snapshot;
        }

        MethodSnapshot detect_ioctl_honeypot() {
            MethodSnapshot snapshot;
            int hit_count = 0;
            std::string last_detail;
            std::vector<std::uint64_t> gaps;
            std::vector<std::uint64_t> noise_floors;
            std::vector<std::uint64_t> ratios;

            for (int attempt = 0; attempt < kRepeatedProbeAttempts; ++attempt) {
                const MethodSnapshot single = run_single_ioctl_honeypot_probe(attempt);
                if (!single.detail.empty()) {
                    last_detail = single.detail;
                }
                snapshot.timer_source = single.timer_source;
                snapshot.timer_fallback_reason = single.timer_fallback_reason;
                snapshot.affinity_status = single.affinity_status;
                if (single.honeypot_median_gap_ns > 0 ||
                    single.honeypot_median_noise_floor_ns > 0 ||
                    single.honeypot_median_ratio_percent > 0) {
                    gaps.push_back(single.honeypot_median_gap_ns);
                    noise_floors.push_back(single.honeypot_median_noise_floor_ns);
                    ratios.push_back(static_cast<std::uint64_t>(single.honeypot_median_ratio_percent));
                }
                if (!single.detected) {
                    continue;
                }
                ++hit_count;
                if (snapshot.findings.empty()) {
                    snapshot.findings = single.findings;
                }
            }

            const auto gap_stats = ducktee::common::summarize_samples(gaps);
            const auto noise_stats = ducktee::common::summarize_samples(noise_floors);
            const auto ratio_stats = ducktee::common::summarize_samples(ratios);
            snapshot.honeypot_run_count = kRepeatedProbeAttempts;
            snapshot.honeypot_suspicious_run_count = hit_count;
            snapshot.honeypot_median_gap_ns = gap_stats.median_ns;
            snapshot.honeypot_gap_mad_ns = gap_stats.mad_ns;
            snapshot.honeypot_median_noise_floor_ns = noise_stats.median_ns;
            snapshot.honeypot_median_ratio_percent = static_cast<int>(ratio_stats.median_ns);
            snapshot.detected = hit_count >= 2;
            std::ostringstream builder;
            if (snapshot.detected) {
                builder << "Keystore-style binder honeypot triggered on " << hit_count
                        << "/" << kRepeatedProbeAttempts << " timing runs."
                        << " median_gap=" << snapshot.honeypot_median_gap_ns << "ns"
                        << ", gap_mad=" << snapshot.honeypot_gap_mad_ns << "ns"
                        << ", noise_floor=" << snapshot.honeypot_median_noise_floor_ns << "ns"
                        << ", median_ratio=" << snapshot.honeypot_median_ratio_percent << "%.";
                snapshot.detail = builder.str();
            } else {
                builder << "Keystore-style binder honeypot stayed within normal bounds across "
                        << kRepeatedProbeAttempts << " runs";
                if (hit_count > 0) {
                    builder << " (" << hit_count << "/" << kRepeatedProbeAttempts
                            << " suspicious run).";
                } else {
                    builder << ".";
                }
                if (gap_stats.available) {
                    builder << " median_gap=" << snapshot.honeypot_median_gap_ns << "ns"
                            << ", gap_mad=" << snapshot.honeypot_gap_mad_ns << "ns"
                            << ", noise_floor=" << snapshot.honeypot_median_noise_floor_ns << "ns"
                            << ", median_ratio=" << snapshot.honeypot_median_ratio_percent << "%.";
                }
                if (!last_detail.empty()) {
                    builder << " " << last_detail;
                }
                snapshot.detail = builder.str();
            }
            return snapshot;
        }

    }  // namespace

    ProbeSnapshot inspect_process() {
        ProbeSnapshot snapshot;
        std::vector<std::string> methods;
        std::vector<std::string> findings;

        std::vector<std::string> map_hits;
        if (maps_contain_trickystore(&map_hits)) {
            snapshot.detected = true;
            methods.push_back("MAPS_NAME_HIT");
            if (!map_hits.empty()) {
                findings.push_back("Suspicious process map entry: " + map_hits.front());
            }
        }

        const MethodSnapshot got_result = detect_got_ioctl_hook();
        if (got_result.detected) {
            snapshot.detected = true;
            snapshot.got_hook_detected = true;
            methods.push_back("GOT_HOOK");
            findings.insert(findings.end(), got_result.findings.begin(), got_result.findings.end());
        }

        const MethodSnapshot syscall_result = detect_syscall_ioctl_mismatch();
        if (syscall_result.detected) {
            snapshot.syscall_mismatch_detected = true;
            methods.push_back("SYSCALL_MISMATCH");
            findings.insert(findings.end(), syscall_result.findings.begin(),
                            syscall_result.findings.end());
        }

        const MethodSnapshot inline_result = detect_ioctl_inline_hook();
        if (inline_result.detected) {
            snapshot.detected = true;
            snapshot.inline_hook_detected = true;
            methods.push_back("INLINE_HOOK");
            findings.insert(findings.end(), inline_result.findings.begin(),
                            inline_result.findings.end());
        }

        const MethodSnapshot honeypot_result = detect_ioctl_honeypot();
        snapshot.timer_source = honeypot_result.timer_source;
        snapshot.timer_fallback_reason = honeypot_result.timer_fallback_reason;
        snapshot.affinity_status = honeypot_result.affinity_status;
        snapshot.honeypot_run_count = honeypot_result.honeypot_run_count;
        snapshot.honeypot_suspicious_run_count = honeypot_result.honeypot_suspicious_run_count;
        snapshot.honeypot_median_gap_ns = honeypot_result.honeypot_median_gap_ns;
        snapshot.honeypot_gap_mad_ns = honeypot_result.honeypot_gap_mad_ns;
        snapshot.honeypot_median_noise_floor_ns = honeypot_result.honeypot_median_noise_floor_ns;
        snapshot.honeypot_median_ratio_percent = honeypot_result.honeypot_median_ratio_percent;
        if (honeypot_result.detected) {
            snapshot.detected = true;
            snapshot.honeypot_detected = true;
            methods.push_back("HONEYPOT");
            findings.insert(findings.end(), honeypot_result.findings.begin(),
                            honeypot_result.findings.end());
        }

        snapshot.methods = methods;
        if (!findings.empty()) {
            std::ostringstream builder;
            builder << "methods=";
            for (std::size_t index = 0; index < methods.size(); ++index) {
                if (index > 0) {
                    builder << ",";
                }
                builder << methods[index];
            }
            builder << " | " << findings.front();
            snapshot.details = builder.str();
        } else if (snapshot.syscall_mismatch_detected) {
            snapshot.details = syscall_result.detail;
        } else {
            std::ostringstream builder;
            builder << got_result.detail
                    << " | " << inline_result.detail
                    << " | " << honeypot_result.detail;
            snapshot.details = builder.str();
        }
        return snapshot;
    }

}  // namespace ducktee::trickystore
