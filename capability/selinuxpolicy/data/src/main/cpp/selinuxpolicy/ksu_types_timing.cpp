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

#include "selinuxpolicy/context_validity_internal.h"
#include "common/arm64_counter.h"
#include "common/disposable_child.h"
#include "selinuxpolicy/avc_lookup_probe.h"
#include "selinuxpolicy/raw_context_node.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <new>
#include <numeric>
#include <optional>
#include <sched.h>
#include <unistd.h>

namespace {

    constexpr int kBatchCount = 9;
    constexpr int kQueriesPerBatch = 1'500;
    constexpr int kWarmupPairs = 32;
    constexpr jlong kPairTieThresholdNs = 40;
    constexpr char kInvalidContext[] = "u:r:inv:s0";
    constexpr char kProcSelfAttrCurrent[] = "/proc/self/attr/current";
    using PairDifferences = std::array<jlong, kBatchCount * kQueriesPerBatch>;
    using duckdetector::selinux::query_raw_context_node;
    namespace avc = duckdetector::selinux::avc_lookup;
    namespace common = duckdetector::common;

    struct TimingSamples {
        std::array<jlong, kBatchCount> batch_differences{};
        std::array<jlong, 2 * kBatchCount> batch_direction_counts{};
        jlong median_pair_ns = 0;
    };

    class ScopedCpuAffinity {
    public:
        explicit ScopedCpuAffinity(int cpu) {
            if (sched_getaffinity(0, sizeof(original_), &original_) != 0) return;
            cpu_set_t requested;
            CPU_ZERO(&requested);
            CPU_SET(cpu, &requested);
            pinned_ = sched_setaffinity(0, sizeof(requested), &requested) == 0;
        }

        ~ScopedCpuAffinity() {
            if (pinned_) sched_setaffinity(0, sizeof(original_), &original_);
        }

    private:
        cpu_set_t original_{};
        bool pinned_ = false;
    };

    template<typename Sample>
    std::optional<TimingSamples> measure_batches(PairDifferences &differences, const Sample &sample) {
        using duckdetector::selinux::detail::kKsuContext;
        const ScopedCpuAffinity affinity(0);
        for (int batch = 0; batch < kBatchCount; ++batch) {
            const int first_pair = batch == 0 ? -kWarmupPairs : 0;
            const int offset = batch * kQueriesPerBatch;
            for (int pair = first_pair; pair < kQueriesPerBatch; ++pair) {
                const auto a = sample(kKsuContext, true);
                if (!a) return std::nullopt;
                const auto b = sample(kInvalidContext, false);
                if (!b) return std::nullopt;
                if (pair >= 0) {
                    const jlong delta_ns = *a - *b;
                    differences[offset + pair] =
                            delta_ns > -kPairTieThresholdNs && delta_ns < kPairTieThresholdNs
                            ? 0 : delta_ns;
                }
            }
        }
        TimingSamples result;
        for (int batch = 0; batch < kBatchCount; ++batch) {
            const auto first = differences.begin() + batch * kQueriesPerBatch;
            for (auto pair = first; pair != first + kQueriesPerBatch; ++pair) {
                result.batch_differences[batch] += *pair;
                result.batch_direction_counts[2 * batch] += *pair > 0;
                result.batch_direction_counts[2 * batch + 1] += *pair < 0;
            }
        }
        const auto middle = differences.begin() + differences.size() / 2;
        std::nth_element(differences.begin(), middle, differences.end());
        result.median_pair_ns = std::midpoint(*std::max_element(differences.begin(), middle), *middle);
        return result;
    }

    std::optional<jlong> timed_proc_attr_write(const char *context, bool candidate) {
        // The forked child is single-threaded, so /proc/self targets the caller.
        const int fd = open(kProcSelfAttrCurrent, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return std::nullopt;
        const auto length = std::strlen(context);
        std::uint64_t begin, end;
        if (!common::arm64_counter::read_time_ns(&begin)) {
            close(fd);
            return std::nullopt;
        }
        const ssize_t written = write(fd, context, length);
        const int error = errno;
        const bool timed = common::arm64_counter::read_time_ns(&end) && end >= begin;
        close(fd);
        if (!timed || written != -1 || (error != EINVAL && !(candidate && error == EACCES))) {
            return std::nullopt;
        }
        return static_cast<jlong>(end - begin);
    }

    std::optional<TimingSamples> measure_proc_attr(PairDifferences &differences) {
        const auto uid = getuid();
        char initial[128]{};
        if (uid < 10000 || avc::read_identity(initial, sizeof(initial))) return std::nullopt;
        constexpr common::ChildDeadlines deadlines{std::chrono::seconds(3), std::chrono::milliseconds(250)};
        TimingSamples samples{};
        auto bytes = std::span(reinterpret_cast<unsigned char *>(&samples), sizeof(samples));
        const auto child = common::run_disposable_child(bytes, deadlines, [&](int report_fd) {
            // Current-domain writes can attempt a real transition. Confine them to
            // this child and stop on any success, short write, or changed identity.
            char current[sizeof(initial)]{};
            char mode[8];
            std::size_t mode_length = 0;
            if (avc::read_identity(current, sizeof(current)) || std::strcmp(initial, current) != 0 ||
                avc::read_text(avc::kEnforce, mode, sizeof(mode), mode_length) || !mode_length || mode[0] != '1' ||
                !timed_proc_attr_write(kInvalidContext, false)) {
                return 1;
            }
            const auto result = measure_batches(differences, timed_proc_attr_write);
            if (!result || getuid() != uid || avc::read_identity(current, sizeof(current)) ||
                std::strcmp(initial, current) != 0) {
                return 1;
            }
            const auto written = write(report_fd, &*result, sizeof(*result));
            return written == static_cast<ssize_t>(sizeof(*result)) ? 0 : 1;
        });
        if (child.end != common::ChildEnd::kExited || child.exit_status != 0 ||
            child.report_length != sizeof(samples)) {
            return std::nullopt;
        }
        return samples;
    }

    jlongArray encode_samples(JNIEnv *env, const TimingSamples &samples) {
        constexpr int kCountOffset = kBatchCount + 1;
        constexpr int kPairCountIndex = kCountOffset + 2 * kBatchCount;
        jlongArray result = env->NewLongArray(kPairCountIndex + 1);
        if (result != nullptr) {
            env->SetLongArrayRegion(result, 0, kBatchCount, samples.batch_differences.data());
            env->SetLongArrayRegion(result, kBatchCount, 1, &samples.median_pair_ns);
            env->SetLongArrayRegion(result, kCountOffset, 2 * kBatchCount, samples.batch_direction_counts.data());
            const jlong pairs_per_batch = kQueriesPerBatch;
            env->SetLongArrayRegion(result, kPairCountIndex, 1, &pairs_per_batch);
        }
        return result;
    }
}  // namespace

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_eltavine_duckdetector_capability_selinuxpolicy_data_SelinuxRawAccess_nativeMeasureKsuContextTiming(
        JNIEnv *env, jobject, jboolean proc_attr
) {
    using namespace duckdetector::selinux::detail;
    const auto carrier = read_process_context();
    if (context_type(carrier) != kExpectedCarrierType) return nullptr;
    const std::unique_ptr<PairDifferences> differences(new (std::nothrow) PairDifferences{});
    if (!differences) return nullptr;
    if (proc_attr) {
        const auto samples = measure_proc_attr(*differences);
        return samples ? encode_samples(env, *samples) : nullptr;
    }

    const auto control = query_raw_context_node(carrier.c_str(), true);
    if (!control.complete || !control.elapsed_ns) return nullptr;
    const auto samples = measure_batches(*differences, [](const char *context, bool candidate) {
        const auto result = query_raw_context_node(context, true);
        return result.rejected() || (candidate && result.complete) ? result.elapsed_ns : std::nullopt;
    });
    return samples ? encode_samples(env, *samples) : nullptr;
}
